// QUIC client implementation
// Handles QUIC connections with certificate caching and SSH bootstrap

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use quinn::crypto::rustls::QuicClientConfig as RustlsQuicClientConfig;
use quinn::rustls;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::Error as RustlsError;
use smol::io::{AsyncRead, AsyncWrite};
use std::convert::TryFrom;
use std::io::{Cursor, Read};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

#[cfg(feature = "quic")]
use x509_parser::prelude::*;

/// Wraps a quinn bidirectional stream to implement AsyncReadAndWrite
///
/// Quinn provides futures-based streams which we adapt to the AsyncRead/AsyncWrite
/// trait interface. The key is that quinn's streams already implement
/// futures::io::AsyncRead/AsyncWrite, so we forward those implementations.
#[derive(Debug)]
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        // Quinn's RecvStream uses futures_io::AsyncRead but with quinn::ReadError.
        // We need to forward and convert the error type to std::io::Error.
        // Quinn's trait methods are available through the Deref implementation of Pin.
        match Pin::new(&mut self.recv).poll_read(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("QUIC read error: {:?}", e),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // Quinn's SendStream uses futures_io::AsyncWrite but with quinn::WriteError.
        // We need to forward and convert the error type to std::io::Error.
        // Quinn's trait methods are available through the Deref implementation of Pin.
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!("QUIC write error: {:?}", e),
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        // QUIC doesn't require explicit flushing - data is sent when available
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Try to finish the send stream (non-blocking operation)
        match self.send.finish() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "QUIC send stream already closed or in error state",
            ))),
        }
    }
}

#[async_trait(?Send)]
impl crate::client::AsyncReadAndWrite for QuicStream {}

/// Configure QUIC transport parameters
fn configure_transport(
    config: Option<&config::QuicDomainClient>,
) -> Option<Arc<quinn::TransportConfig>> {
    if let Some(cfg) = config {
        let mut transport = quinn::TransportConfig::default();
        if let Ok(idle_timeout) = quinn::IdleTimeout::try_from(cfg.max_idle_timeout) {
            transport.max_idle_timeout(Some(idle_timeout));
        }
        // Default keep_alive_interval to half of max_idle_timeout if not explicitly set
        let keep_alive = cfg.keep_alive_interval.unwrap_or_else(|| {
            std::time::Duration::from_millis((cfg.max_idle_timeout.as_millis() / 2) as u64)
        });
        transport.keep_alive_interval(Some(keep_alive));
        Some(Arc::new(transport))
    } else {
        None
    }
}

/// Load certificate chain from a PEM file
fn load_certificates_from_file<P: AsRef<Path>>(
    path: P,
) -> anyhow::Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let path = path.as_ref();
    let mut file = std::fs::File::open(path)
        .context(format!("Failed to open certificate file: {}", path.display()))?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .context(format!("Failed to read certificate file: {}", path.display()))?;

    let mut cursor = Cursor::new(&content);
    rustls_pemfile::certs(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .context(format!("Failed to parse certificates from: {}", path.display()))
}

/// Load private key from a PEM file
#[allow(dead_code)]
fn load_private_key_from_file<P: AsRef<Path>>(
    path: P,
) -> anyhow::Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let path = path.as_ref();
    let mut file = std::fs::File::open(path)
        .context(format!("Failed to open private key file: {}", path.display()))?;
    let mut content = Vec::new();
    file.read_to_end(&mut content)
        .context(format!("Failed to read private key file: {}", path.display()))?;

    let mut cursor = Cursor::new(&content);
    loop {
        match rustls_pemfile::read_one(&mut cursor) {
            Ok(Some(item)) => match item {
                rustls_pemfile::Item::Pkcs8Key(key) => {
                    return Ok(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
                }
                rustls_pemfile::Item::Sec1Key(key) => {
                    return Ok(rustls::pki_types::PrivateKeyDer::Sec1(key));
                }
                rustls_pemfile::Item::Pkcs1Key(key) => {
                    return Ok(rustls::pki_types::PrivateKeyDer::Pkcs1(key));
                }
                _ => continue,
            },
            Ok(None) => break,
            Err(e) => {
                anyhow::bail!(
                    "Failed to read private key from {}: {}",
                    path.display(),
                    e
                );
            }
        }
    }

    anyhow::bail!("No private key found in {}", path.display())
}

/// Custom verifier that skips hostname verification but validates certificate chain
/// Used when accept_invalid_hostnames is true - still validates certificate was signed by trusted CA
/// and has not expired, but doesn't check that the hostname matches the certificate CN
#[derive(Debug)]
struct NoHostnameVerification {
    verifier: Arc<rustls::client::WebPkiServerVerifier>,
}

impl NoHostnameVerification {
    fn new(roots: rustls::RootCertStore) -> Self {
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("Failed to build WebPkiServerVerifier");
        Self { verifier }
    }
}

impl ServerCertVerifier for NoHostnameVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Use a dummy hostname for chain validation (it will be ignored)
        // We validate the certificate chain but skip hostname verification
        // This dummy name is valid and will never fail
        let dummy_name = rustls::pki_types::ServerName::try_from("_dummy_")
            .expect("Failed to create dummy hostname (should never happen)");

        // Validate certificate chain and expiration, but hostname check will be skipped
        // since we're not checking against the actual server name
        self.verifier
            .verify_server_cert(end_entity, intermediates, &dummy_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

/// Extract CN (Common Name) from a certificate
/// Returns the CN value if found, None otherwise
#[cfg(feature = "quic")]
fn extract_cn_from_certificate(cert_der: &CertificateDer<'_>) -> anyhow::Result<String> {
    let (_remainder, parsed) = parse_x509_certificate(cert_der.as_ref())
        .context("Failed to parse X.509 certificate")?;

    let subject = &parsed.tbs_certificate.subject;

    // Look for CommonName attribute in the subject DN
    for rdn in subject.iter_common_name() {
        if let Ok(cn) = rdn.as_str() {
            return Ok(cn.to_string());
        }
    }

    Err(anyhow!("Certificate has no CommonName (CN) attribute"))
}

/// Custom verifier that validates certificate chain and a specific CN
/// Used when accept_invalid_hostnames is true but expected_cn is set
/// Validates certificate was signed by trusted CA, has not expired, and has expected CN
#[derive(Debug)]
struct SpecificCNVerification {
    verifier: Arc<rustls::client::WebPkiServerVerifier>,
    expected_cn: String,
}

impl SpecificCNVerification {
    fn new(roots: rustls::RootCertStore, expected_cn: String) -> Self {
        let verifier = rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
            .build()
            .expect("Failed to build WebPkiServerVerifier");
        Self { verifier, expected_cn }
    }

    /// Check if certificate CN matches expected CN using proper X.509 parsing
    fn verify_cn(&self, end_entity: &CertificateDer<'_>) -> bool {
        match extract_cn_from_certificate(end_entity) {
            Ok(cn) => {
                if cn == self.expected_cn {
                    log::trace!(
                        "QUIC client: Certificate CN '{}' matches expected CN '{}'",
                        cn,
                        self.expected_cn
                    );
                    true
                } else {
                    log::error!(
                        "QUIC client: Certificate CN '{}' does not match expected CN '{}'",
                        cn,
                        self.expected_cn
                    );
                    false
                }
            }
            Err(e) => {
                log::error!("QUIC client: Failed to extract CN from certificate: {}", e);
                false
            }
        }
    }
}

impl ServerCertVerifier for SpecificCNVerification {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // First validate the certificate chain
        let dummy_name = rustls::pki_types::ServerName::try_from("_dummy_")
            .expect("Failed to create dummy hostname (should never happen)");

        self.verifier
            .verify_server_cert(end_entity, intermediates, &dummy_name, ocsp_response, now)?;

        // Then verify the CN matches
        if !self.verify_cn(end_entity) {
            // CN validation failed - reject the connection by running the verifier with expected_cn
            // This will cause the standard hostname verification to fail
            log::error!(
                "QUIC: Certificate CN verification failed - expected CN: {}",
                self.expected_cn
            );
            let expected_name = rustls::pki_types::ServerName::try_from(self.expected_cn.as_str())
                .unwrap_or_else(|_| {
                    rustls::pki_types::ServerName::try_from("_invalid_").expect("_invalid_ is valid")
                });
            // Run verification with the expected_cn as hostname - this will fail if CN doesn't match
            return self
                .verifier
                .verify_server_cert(end_entity, intermediates, &expected_name, ocsp_response, now);
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.verifier.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.verifier.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.verifier.supported_verify_schemes()
    }
}

/// Build rustls ClientConfig for QUIC, with optional client certificate and validation options
fn build_rustls_client_config(
    roots: rustls::RootCertStore,
    client_cert_pem: Option<String>,
    accept_invalid_hostnames: bool,
    expected_cn: Option<String>,
) -> anyhow::Result<rustls::ClientConfig> {
    let builder = if accept_invalid_hostnames {
        if let Some(cn) = expected_cn {
            // Validate certificate chain and specific CN, skip other hostname checks
            log::warn!("QUIC: Hostname verification disabled but validating CN='{}' (accept_invalid_hostnames=true)", cn);
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(SpecificCNVerification::new(roots.clone(), cn)))
        } else {
            // Skip all hostname verification but still validate certificate chain
            log::warn!("QUIC: All hostname verification disabled (accept_invalid_hostnames=true) - certificate chain still validated");
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoHostnameVerification::new(roots.clone())))
        }
    } else {
        // Standard verification: validate certificate chain and hostname
        rustls::ClientConfig::builder().with_root_certificates(roots)
    };

    if let Some(cert_pem) = client_cert_pem {
        let mut cert_cursor = Cursor::new(cert_pem.as_bytes());

        // Extract certificate chain
        let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut cert_cursor)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse client certificate")?;

        if certs.is_empty() {
            anyhow::bail!("No certificates found in PEM");
        }

        // Extract private key by reading all PEM items and finding the key
        let mut key_cursor = Cursor::new(cert_pem.as_bytes());
        let mut private_key: Option<rustls::pki_types::PrivateKeyDer> = None;

        loop {
            match rustls_pemfile::read_one(&mut key_cursor) {
                Ok(Some(item)) => {
                    match item {
                        rustls_pemfile::Item::Pkcs8Key(key) => {
                            private_key = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
                            break;
                        }
                        rustls_pemfile::Item::Sec1Key(key) => {
                            private_key = Some(rustls::pki_types::PrivateKeyDer::Sec1(key));
                            break;
                        }
                        rustls_pemfile::Item::X509Certificate(_) => {
                            // Skip certificates, we already have them
                            continue;
                        }
                        _ => {
                            // Skip other items
                            continue;
                        }
                    }
                }
                Ok(None) => break,
                Err(e) => {
                    anyhow::bail!("Failed to read private key from PEM: {}", e);
                }
            }
        }

        let private_key = private_key.ok_or_else(|| anyhow!("No private key found in PEM"))?;

        // Build config with client certificate
        builder
            .with_client_auth_cert(certs, private_key)
            .context("Failed to configure client certificate")
    } else {
        // Build config without client certificate
        Ok(builder.with_no_client_auth())
    }
}

/// Establish a QUIC connection to a remote mux server
pub async fn establish_quic_connection(
    remote_address: &str,
    client_cert_pem: Option<String>,
    ca_cert_pem: Option<String>,
    config: Option<&config::QuicDomainClient>,
) -> anyhow::Result<Box<dyn crate::client::AsyncReadAndWrite>> {
    use std::net::ToSocketAddrs;

    // Extract hostname for SNI
    let hostname = remote_address
        .split(':')
        .next()
        .ok_or_else(|| anyhow!("Missing hostname in remote_address"))?;

    // Resolve hostname to socket address (handles both IPs and domain names)
    // This mirrors what TcpStream::connect does
    let socket_addr: std::net::SocketAddr = remote_address
        .to_socket_addrs()
        .context(format!("Failed to resolve address: {}", remote_address))?
        .next()
        .ok_or_else(|| anyhow!("No addresses found for {}", remote_address))?;

    // Extract configuration options
    let enable_migration = config.map(|c| c.enable_migration).unwrap_or(true);
    let accept_invalid_hostnames = config.map(|c| c.accept_invalid_hostnames).unwrap_or(false);
    let expected_cn = config.and_then(|c| c.expected_cn.clone());

    // Determine which hostname to use for certificate verification
    // If expected_cn is specified, use it; otherwise use the extracted hostname
    let verify_hostname = expected_cn.as_deref().unwrap_or(hostname);

    if enable_migration {
        log::debug!("Connection migration enabled - will handle network changes transparently");
    }

    if accept_invalid_hostnames {
        log::warn!("QUIC: Hostname verification disabled for {}", hostname);
    }

    if let Some(cn) = &expected_cn {
        log::debug!("QUIC: Using custom expected_cn for certificate verification: {}", cn);
    }

    // Create QUIC endpoint bound to any local address
    // Note: Connection migration is handled transparently by Quinn's protocol implementation.
    // If the network changes (e.g., WiFi to Ethernet), Quinn will automatically validate
    // the new path and continue the connection. The enable_migration flag ensures
    // we're using the default Quinn settings that support this.
    let mut endpoint =
        quinn::Endpoint::client("[::]:0".parse()?).context("Failed to create QUIC endpoint")?;

    // Build root certificate store
    let mut roots = rustls::RootCertStore::empty();

    // Priority: config file paths > memory certs > system roots
    let ca_loaded = if let Some(cfg) = config {
        let mut loaded_any = false;

        // Load CA certificate from file path if configured
        if let Some(ca_path) = &cfg.pem_ca {
            match load_certificates_from_file(ca_path) {
                Ok(certs) => {
                    log::debug!("QUIC: Loading CA certificate from file: {}", ca_path.display());
                    for cert in certs {
                        roots
                            .add(cert)
                            .context("Failed to add CA certificate from file")?;
                    }
                    loaded_any = true;
                }
                Err(e) => log::warn!("Failed to load CA from file: {}", e),
            }
        }

        // Load additional root certificates from pem_root_certs paths
        for root_cert_path in &cfg.pem_root_certs {
            match load_certificates_from_file(root_cert_path) {
                Ok(certs) => {
                    log::debug!(
                        "QUIC: Loading additional root certificate from: {}",
                        root_cert_path.display()
                    );
                    for cert in certs {
                        roots
                            .add(cert)
                            .context("Failed to add additional root certificate")?;
                    }
                    loaded_any = true;
                }
                Err(e) => log::warn!("Failed to load root certificate: {}", e),
            }
        }

        loaded_any
    } else {
        false
    };

    // If no CA loaded from files, try memory cert, then fall back to system roots
    if !ca_loaded {
        if let Some(ca_pem) = ca_cert_pem {
            let mut cursor = Cursor::new(ca_pem.as_bytes());
            let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .context("Failed to parse CA certificate")?;

            for cert in certs {
                roots
                    .add(cert)
                    .context("Failed to add CA certificate to root store")?;
            }
        } else {
            // Fallback to system roots if no custom CA provided
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }

    // Load client certificate from pem_cert and pem_private_key files if configured
    let client_cert_for_config = if let Some(cfg) = config {
        if let Some(cert_path) = &cfg.pem_cert {
            if let Some(key_path) = &cfg.pem_private_key {
                // Load certificate and key from files as PEM strings
                log::debug!("QUIC: Loading client certificate from file: {}", cert_path.display());
                log::debug!("QUIC: Loading client private key from file: {}", key_path.display());

                match (
                    std::fs::read_to_string(cert_path),
                    std::fs::read_to_string(key_path),
                ) {
                    (Ok(cert_pem), Ok(key_pem)) => {
                        // Combine certificate and key PEM data
                        Some(format!("{}{}", cert_pem, key_pem))
                    }
                    (Err(e), _) => {
                        log::warn!(
                            "Failed to load client certificate from {}: {}",
                            cert_path.display(),
                            e
                        );
                        client_cert_pem
                    }
                    (_, Err(e)) => {
                        log::warn!(
                            "Failed to load client private key from {}: {}",
                            key_path.display(),
                            e
                        );
                        client_cert_pem
                    }
                }
            } else {
                log::warn!("pem_cert configured but pem_private_key missing, using memory cert");
                client_cert_pem
            }
        } else {
            client_cert_pem
        }
    } else {
        client_cert_pem
    };

    // Build rustls client config (with or without client certificate)
    // Note: we pass expected_cn for CN validation when accept_invalid_hostnames is enabled
    // client_cert_for_config is from files if configured, otherwise uses memory cert from SSH bootstrap
    let client_crypto = build_rustls_client_config(roots, client_cert_for_config, accept_invalid_hostnames, expected_cn.clone())?;

    let quic_client_config = RustlsQuicClientConfig::try_from(client_crypto)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    // Apply transport configuration from config
    if let Some(transport) = configure_transport(config) {
        client_config.transport_config(transport);
    }

    endpoint.set_default_client_config(client_config);

    // Connect to server
    // Use verify_hostname for certificate verification (may be expected_cn if configured)
    // SNI will still be sent correctly for proper server identification
    log::info!("QUIC: Initiating connection to {} (hostname: {}, verify_hostname: {})", socket_addr, hostname, verify_hostname);
    let connecting = endpoint
        .connect(socket_addr, verify_hostname)
        .context("Failed to create QUIC connection")?;

    // Do a standard 1-RTT handshake
    log::debug!("QUIC: Performing 1-RTT handshake");
    let connection = connecting.await.context("QUIC handshake failed")?;

    log::info!("QUIC: Connection established, opening bidirectional stream");
    // Open a bidirectional stream for mux protocol
    let (send, recv) = connection
        .open_bi()
        .await
        .context("Failed to open QUIC stream")?;

    log::debug!("QUIC: Stream opened successfully");

    let stream = Box::new(QuicStream::new(send, recv));
    Ok(stream)
}
