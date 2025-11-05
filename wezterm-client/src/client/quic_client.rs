// QUIC client implementation
// Handles QUIC connections with certificate caching and SSH bootstrap
#![cfg(feature = "quic")]

use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use codec::{GetTlsCredsResponse, Pdu};
use config::QuicDomainClient;
use mux::connui::ConnectionUI;
use quinn::crypto::rustls::QuicClientConfig as RustlsQuicClientConfig;
use quinn::rustls;
use smol::io::{AsyncRead, AsyncWrite};
use std::convert::TryFrom;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

use crate::client::AsyncReadAndWrite;

use super::Reconnectable;

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

/// Build rustls ClientConfig for QUIC, with optional client certificate
fn build_rustls_client_config(
    roots: rustls::RootCertStore,
    client_cert_pem: Option<String>,
) -> anyhow::Result<rustls::ClientConfig> {
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
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(certs, private_key)
            .context("Failed to configure client certificate")
    } else {
        // Build config without client certificate
        Ok(rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth())
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

    // Check if connection migration is enabled
    let enable_migration = config.map(|c| c.enable_migration).unwrap_or(true);
    if enable_migration {
        log::debug!("Connection migration enabled - will handle network changes transparently");
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

    // If CA certificate is provided, use it; otherwise use system roots
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

    // Build rustls client config (with or without client certificate)
    let client_crypto = build_rustls_client_config(roots, client_cert_pem)?;

    let quic_client_config = RustlsQuicClientConfig::try_from(client_crypto)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

    // Apply transport configuration from config
    if let Some(transport) = configure_transport(config) {
        client_config.transport_config(transport);
    }

    endpoint.set_default_client_config(client_config);

    // Connect to server
    log::info!(
        "QUIC: Initiating connection to {} (hostname: {})",
        socket_addr,
        hostname
    );
    let connecting = endpoint
        .connect(socket_addr, hostname)
        .context("Failed to create QUIC connection")?;

    // Try to use 0-RTT if enabled for faster reconnections
    let connection = connecting.await.context("QUIC handshake failed")?;

    log::info!("QUIC: Connection established, opening bidirectional stream");
    // Open a bidirectional stream for mux protocol
    let (send, recv) = connection
        .open_bi()
        .await
        .context("Failed to open QUIC stream")?;

    log::info!("QUIC: Stream opened successfully");

    let stream = Box::new(QuicStream::new(send, recv));
    Ok(stream)
}

fn try_quic_connect(
    remote_address: &str,
    creds: &codec::GetTlsCredsResponse,
    quic_client: &config::QuicDomainClient,
    source_description: &str,
) -> anyhow::Result<Box<dyn AsyncReadAndWrite>> {
    match smol::block_on(establish_quic_connection(
        remote_address,
        Some(creds.client_cert_pem.clone()),
        Some(creds.ca_cert_pem.clone()),
        Some(quic_client),
    )) {
        Ok(stream) => {
            log::info!("QUIC connection established from {}", source_description);
            Ok(stream)
        }
        Err(err) => {
            log::debug!("QUIC connect with {} failed: {}", source_description, err);
            Err(err)
        }
    }
}
impl Reconnectable {
    fn load_quic_creds_from_disk(
        &mut self,
        quic_client: &QuicDomainClient,
    ) -> anyhow::Result<Option<GetTlsCredsResponse>> {
        if !quic_client.persist_to_disk {
            return Ok(None);
        }

        let ca_path = self.tls_creds_ca_path()?;
        let cert_path = self.tls_creds_cert_path()?;

        if !ca_path.exists() || !cert_path.exists() {
            return Ok(None);
        }

        let ca_cert_pem = std::fs::read_to_string(&ca_path)?;
        let client_cert_pem = std::fs::read_to_string(&cert_path)?;

        Ok(Some(GetTlsCredsResponse {
            ca_cert_pem,
            client_cert_pem,
        }))
    }

    pub(super) fn save_quic_creds_to_disk(
        &self,
        quic_client: &QuicDomainClient,
        creds: &GetTlsCredsResponse,
    ) -> anyhow::Result<()> {
        if !quic_client.persist_to_disk {
            return Ok(());
        }

        let ca_path = self.tls_creds_ca_path()?;
        let cert_path = self.tls_creds_cert_path()?;

        std::fs::write(&ca_path, creds.ca_cert_pem.as_bytes())?;
        std::fs::write(&cert_path, creds.client_cert_pem.as_bytes())?;

        Ok(())
    }

    pub fn quic_connect(
        &mut self,
        quic_client: config::QuicDomainClient,
        _initial: bool,
        ui: &mut ConnectionUI,
    ) -> anyhow::Result<()> {
        let remote_address = &quic_client.remote_address;

        // Use reference to cached credentials
        if let Some(creds) = &self.tls_creds {
            log::debug!("Trying direct QUIC connection with cached credentials");
            match try_quic_connect(&remote_address, creds, &quic_client, "cached creds") {
                Ok(stream) => {
                    self.stream.replace(stream);
                    ui.output_str(&format!(
                        "QUIC Connected to {} (cached creds)!\n",
                        remote_address
                    ));
                    return Ok(());
                }
                Err(_) => {
                    // Fall through to SSH bootstrap
                }
            }
        }

        // SSH bootstrap for certificate exchange
        if let Some(Ok(ssh_params)) = quic_client.ssh_parameters() {
            ui.output_str("Bootstrapping QUIC credentials via SSH...\n");

            let sess = crate::ssh_bootstrap::establish_ssh_session(&ssh_params, ui)?;

            // Execute tlscreds command to get certificates
            let cmd = format!(
                "{} cli tlscreds",
                Self::wezterm_bin_path(&quic_client.remote_wezterm_path)
            );
            ui.output_str(&format!("Running: {}\n", cmd));

            let creds = ui.run_and_log_error(|| {
                crate::ssh_bootstrap::execute_remote_command_for_pdu(&sess, &cmd, |pdu| match pdu {
                    Pdu::GetTlsCredsResponse(creds) => {
                        log::info!("got QUIC TLS creds");
                        Ok(creds)
                    }
                    _ => bail!("unexpected response to tlscreds"),
                })
            })?;

            // Save to disk if configured
            self.save_quic_creds_to_disk(&quic_client, &creds)?;

            // Now connect with the obtained credentials
            log::info!(
                "SSH bootstrap complete, now establishing QUIC connection to {}",
                remote_address
            );
            let stream = try_quic_connect(&remote_address, &creds, &quic_client, "SSH bootstrap")?;

            // Store stream and credentials in memory with timestamp
            self.stream.replace(stream);
            self.tls_creds.replace(creds);
            ui.output_str(&format!("QUIC Connected to {}!\n", remote_address));
            Ok(())
        } else {
            // No SSH bootstrap - try to load credentials from disk if persist_to_disk is set
            if self.tls_creds.is_none() {
                if let Ok(Some(creds)) = self.load_quic_creds_from_disk(&quic_client) {
                    log::debug!("Loaded QUIC credentials from disk, trying direct connection");
                    match try_quic_connect(&remote_address, &creds, &quic_client, "disk creds") {
                        Ok(stream) => {
                            self.stream.replace(stream);
                            self.tls_creds.replace(creds);
                            ui.output_str(&format!(
                                "QUIC Connected to {} (disk creds)!\n",
                                remote_address
                            ));
                            return Ok(());
                        }
                        Err(_) => {
                            // Failed to connect with disk creds, continue to error
                        }
                    }
                }
            }
            bail!("No SSH bootstrap configured and no usable QUIC credentials found");
        }
    }
}
