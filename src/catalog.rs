use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex;
use url::Url;

use crate::artifact_input::{self, SigningPolicy};
use crate::model::{Artifact, MAX_ARTIFACT_BYTES, Platform};
use crate::service::{ServiceError, ShareConfig, ShareService, describe_artifact};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

const RETIRED_BUILD_SECONDS: u64 = 24 * 60 * 60;
const INDEX: &str = "index.json";
const ARTIFACT_METADATA: &str = "artifact.json";

#[derive(Default, Deserialize, Serialize)]
struct Index {
    current: BTreeMap<String, String>,
    retired: BTreeMap<String, u64>,
}

impl Index {
    fn available(&self) -> HashSet<&str> {
        let now = unix_time();
        self.current
            .values()
            .map(String::as_str)
            .chain(self.retired.iter().filter_map(|(id, retired_at)| {
                (now.saturating_sub(*retired_at) < RETIRED_BUILD_SECONDS).then_some(id.as_str())
            }))
            .collect()
    }
}

enum BuildLookup<'a> {
    Channel(&'a str),
    Id(&'a str),
}

pub struct Catalog {
    root: PathBuf,
    base_url: Url,
    // Grants must be shared between the page, manifest and package requests.
    services: Mutex<HashMap<String, Arc<ShareService>>>,
}

impl Catalog {
    pub fn new(root: PathBuf, base_url: Url) -> Self {
        Self {
            root,
            base_url,
            services: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) async fn latest(
        &self,
        product: &str,
        platform: Platform,
    ) -> Result<Arc<ShareService>, ServiceError> {
        self.resolve(BuildLookup::Channel(&channel(product, platform)))
            .await
    }

    pub(crate) async fn build(&self, id: &str) -> Result<Arc<ShareService>, ServiceError> {
        self.resolve(BuildLookup::Id(id)).await
    }

    async fn resolve(&self, lookup: BuildLookup<'_>) -> Result<Arc<ShareService>, ServiceError> {
        // Read the index under the same lock as the cache so an older snapshot
        // cannot evict grants opened against a more recent index.
        let mut services = self.services.lock().await;
        let index = match tokio::fs::read(self.root.join(INDEX)).await {
            Ok(bytes) => decode_index(&bytes)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => Index::default(),
            Err(error) => return Err(error.into()),
        };
        let available = index.available();
        services.retain(|id, _| available.contains(id.as_str()));
        let id = match lookup {
            BuildLookup::Channel(channel) => index
                .current
                .get(channel)
                .map(String::as_str)
                .ok_or_else(|| {
                    ServiceError::NotFound(format!("no build has been published for /{channel}"))
                })?,
            BuildLookup::Id(id) => id,
        };
        if !available.contains(id) || !valid_build_id(id) {
            return Err(ServiceError::NotFound("artifact not found".into()));
        }
        if let Some(service) = services.get(id) {
            return Ok(Arc::clone(service));
        }
        let directory = self.root.join("builds").join(id);
        let bytes = tokio::fs::read(directory.join(ARTIFACT_METADATA)).await?;
        let artifact: Artifact = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if artifact.id != id {
            return Err(
                io::Error::other("stored artifact metadata does not match its directory").into(),
            );
        }
        let service = Arc::new(ShareService::from_staged_artifact(
            &directory,
            vec![self.base_url.clone()],
            artifact,
            ShareConfig::default(),
        ));
        services.insert(id.to_owned(), Arc::clone(&service));
        Ok(service)
    }
}

pub fn valid_product(product: &str) -> bool {
    product != "install"
        && !product.is_empty()
        && product.len() <= 64
        && product.as_bytes()[0].is_ascii_alphanumeric()
        && product
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub fn publish(
    root: &Path,
    product: &str,
    platform: Platform,
    source: &Path,
    signing_policy: SigningPolicy,
) -> Result<Artifact, BoxError> {
    if !valid_product(product) {
        return Err("product must be a lowercase name using letters, digits or hyphens; install is reserved".into());
    }
    let builds = root.join("builds");
    fs::create_dir_all(&builds)?;
    let incoming = tempfile::Builder::new()
        .prefix("incoming-")
        .tempdir_in(root)?;
    // Inspect the bytes we will serve, even if a build script rewrites the input.
    let source_metadata = fs::symlink_metadata(source)?;
    let snapshot = if source_metadata.is_file() {
        if source_metadata.len() > MAX_ARTIFACT_BYTES {
            return Err(
                format!("build exceeds the {MAX_ARTIFACT_BYTES}-byte package limit").into(),
            );
        }
        let path = incoming
            .path()
            .join(source.file_name().ok_or("missing build filename")?);
        fs::copy(source, &path)?;
        path
    } else {
        source.to_owned()
    };
    let prepared = artifact_input::prepare(&snapshot, None, incoming.path(), signing_policy)?;
    let artifact = describe_artifact(prepared.metadata());
    if artifact.platform() != platform {
        return Err(format!(
            "the build targets {}, not {}",
            artifact.platform().path(),
            platform.path()
        )
        .into());
    }
    for warning in prepared.warnings() {
        eprintln!("Warning: {warning}");
    }
    let staged = tempfile::Builder::new()
        .prefix("staged-")
        .tempdir_in(root)?;
    fs::rename(
        prepared.path(),
        staged
            .path()
            .join(format!("{}.{}", artifact.id, artifact.download_extension())),
    )?;
    if let Some(icon) = &prepared.metadata().icon_png {
        fs::write(
            staged.path().join(format!("{}.icon.png", artifact.id)),
            icon,
        )?;
    }
    fs::write(
        staged.path().join(ARTIFACT_METADATA),
        serde_json::to_vec(&artifact)?,
    )?;

    // Only the short promotion and pruning step serializes concurrent publishers.
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join("publish.lock"))?;
    lock.lock()?;
    let index_path = root.join(INDEX);
    let mut index = match fs::read(&index_path) {
        Ok(bytes) => decode_index(&bytes)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => Index::default(),
        Err(error) => return Err(error.into()),
    };
    let now = unix_time();
    if let Some(previous) = index
        .current
        .insert(channel(product, platform), artifact.id.clone())
    {
        index.retired.insert(previous, now);
    }
    index
        .retired
        .retain(|_, retired_at| now.saturating_sub(*retired_at) < RETIRED_BUILD_SECONDS);
    let mut next = tempfile::NamedTempFile::new_in(root)?;
    next.write_all(&serde_json::to_vec(&index)?)?;
    next.as_file().sync_all()?;
    let build_dir = builds.join(&artifact.id);
    fs::rename(staged.path(), &build_dir)?;
    if let Err(error) = next.persist(index_path) {
        let _ = fs::remove_dir_all(build_dir);
        return Err(error.into());
    }

    // Publication is already committed. A cleanup error must not misreport it
    // as failed. A later publish retries pruning unreferenced build directories.
    if let Err(error) = prune(&builds, &index) {
        eprintln!("Warning: could not prune retired builds: {error}");
    }
    Ok(artifact)
}

fn prune(builds: &Path, index: &Index) -> io::Result<()> {
    let available = index.available();
    for entry in fs::read_dir(builds)? {
        let entry = entry?;
        if let Some(id) = entry.file_name().to_str()
            && valid_build_id(id)
            && !available.contains(id)
            && entry.file_type()?.is_dir()
        {
            fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

fn decode_index(bytes: &[u8]) -> io::Result<Index> {
    serde_json::from_slice(bytes)
        .map_err(|error| io::Error::other(format!("invalid catalog index: {error}")))
}

fn valid_build_id(id: &str) -> bool {
    id.strip_prefix("artifact-")
        .is_some_and(|uuid| uuid.len() == 36 && uuid::Uuid::try_parse(uuid).is_ok())
}

fn channel(product: &str, platform: Platform) -> String {
    format!("{product}/{}", platform.path())
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
