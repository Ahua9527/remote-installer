use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::pki_types::pem::{Error as PemError, PemObject};
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio_rustls::rustls::{
    Error as TlsError, InconsistentKeys, ServerConfig, client::verify_server_name,
    server::ParsedCertificate,
};
use url::{Host, Url};

pub struct LocalExposure {
    pub listener: TcpListener,
    pub base_url: Url,
    pub tls: TlsAcceptor,
}

impl LocalExposure {
    pub async fn bind(
        address: SocketAddr,
        host: &str,
        cert: &Path,
        key: &Path,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let invalid_host = || {
            format!("invalid --host {host:?}; use a bare DNS name or IP address covered by --cert")
        };
        let url_host = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip)) => Host::Ipv4(ip),
            Ok(IpAddr::V6(ip)) => Host::Ipv6(ip),
            Err(_) => Host::parse(host).map_err(|_| invalid_host())?,
        };
        let server_name = match &url_host {
            Host::Domain(domain) => {
                ServerName::try_from(domain.clone()).map_err(|_| invalid_host())?
            }
            Host::Ipv4(ip) => ServerName::from(IpAddr::V4(*ip)),
            Host::Ipv6(ip) => ServerName::from(IpAddr::V6(*ip)),
        };
        let mut base_url = Url::parse(&format!("https://{url_host}"))?;

        let cert_error = |error| {
            format!(
                "could not read PEM certificate chain {}: {error}",
                cert.display()
            )
        };
        let chain = CertificateDer::pem_file_iter(cert)
            .map_err(cert_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(cert_error)?;
        let leaf = chain.first().ok_or_else(|| {
            format!(
                "no PEM certificates found in {}; pass fullchain.pem to --cert",
                cert.display()
            )
        })?;
        let parsed = ParsedCertificate::try_from(leaf)
            .map_err(|error| format!("invalid leaf certificate in {}: {error}", cert.display()))?;
        verify_server_name(&parsed, &server_name).map_err(|error| {
            format!(
                "certificate {} does not cover --host {host:?}: {error}",
                cert.display()
            )
        })?;
        let private_key = PrivateKeyDer::from_pem_file(key).map_err(|error| match error {
            PemError::Io(error) => {
                format!("could not read PEM private key {}: {error}", key.display())
            }
            // PEM parse errors can contain input text from a malformed file.
            _ => format!(
                "invalid PEM private key {}; pass an unencrypted private key to --key",
                key.display()
            ),
        })?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(chain, private_key)
            .map_err(|error| match error {
                TlsError::InconsistentKeys(InconsistentKeys::KeyMismatch) => format!(
                    "private key {} does not match certificate {}",
                    key.display(),
                    cert.display()
                ),
                _ => format!(
                    "could not configure TLS with certificate {} and private key {}: {error}",
                    cert.display(),
                    key.display()
                ),
            })?;

        let listener = TcpListener::bind(address).await.map_err(|error| {
            let hint = match error.kind() {
                std::io::ErrorKind::AddrInUse | std::io::ErrorKind::PermissionDenied => {
                    "; choose another port with --https-port or --listen"
                }
                _ => "",
            };
            format!("could not bind Local HTTPS to {address}: {error}{hint}")
        })?;
        base_url
            .set_port(Some(listener.local_addr()?.port()))
            .expect("HTTPS URLs accept ports");
        Ok(Self {
            listener,
            base_url,
            tls: TlsAcceptor::from(Arc::new(config)),
        })
    }
}
