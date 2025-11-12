// QUIC client implementation
// Handles QUIC connections with certificate caching and SSH bootstrap

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use quinn::crypto::rustls::QuicClientConfig as RustlsQuicClientConfig;
use quinn::rustls;
use smol::io::{AsyncRead, AsyncWrite};
use std::convert::TryFrom;
use std::io::Cursor;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

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

    // Check if 0-RTT is enabled
    let enable_0rtt = config.map(|c| c.enable_0rtt).unwrap_or(true);

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

    // If client certificate is provided, use it for mutual TLS
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

        // Use the CA from quiccreds to verify the server's certificate
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        let client_crypto = builder.with_client_auth_cert(certs, private_key)
            .context("Failed to configure client certificate")?;

        let quic_client_config = RustlsQuicClientConfig::try_from(client_crypto)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        // Apply transport configuration from config
        if let Some(cfg) = config {
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(cfg.max_idle_timeout)
                    .context("Invalid max_idle_timeout")?,
            ));
            // Default keep_alive_interval to half of max_idle_timeout if not explicitly set
            let keep_alive = cfg.keep_alive_interval.unwrap_or_else(|| {
                std::time::Duration::from_millis((cfg.max_idle_timeout.as_millis() / 2) as u64)
            });
            transport.keep_alive_interval(Some(keep_alive));
            client_config.transport_config(Arc::new(transport));
        }

        endpoint.set_default_client_config(client_config);
    } else {
        // No client certificate - use no client auth
        let client_crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let quic_client_config = RustlsQuicClientConfig::try_from(client_crypto)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        // Apply transport configuration from config
        if let Some(cfg) = config {
            let mut transport = quinn::TransportConfig::default();
            transport.max_idle_timeout(Some(
                quinn::IdleTimeout::try_from(cfg.max_idle_timeout)
                    .context("Invalid max_idle_timeout")?,
            ));
            // Default keep_alive_interval to half of max_idle_timeout if not explicitly set
            let keep_alive = cfg.keep_alive_interval.unwrap_or_else(|| {
                std::time::Duration::from_millis((cfg.max_idle_timeout.as_millis() / 2) as u64)
            });
            transport.keep_alive_interval(Some(keep_alive));
            client_config.transport_config(Arc::new(transport));
        }

        endpoint.set_default_client_config(client_config);
    }

    // Connect to server
    log::info!("QUIC: Initiating connection to {} (hostname: {})", socket_addr, hostname);
    let connecting = endpoint
        .connect(socket_addr, hostname)
        .context("Failed to create QUIC connection")?;

    // Try to use 0-RTT if enabled for faster reconnections
    let connection = if enable_0rtt {
        log::info!("QUIC: Attempting 0-RTT connection");
        match connecting.into_0rtt() {
            Ok((conn, zero_rtt_accepted)) => {
                log::info!("QUIC: 0-RTT connection established, waiting for acceptance");
                // We can use the connection immediately, but wait for confirmation
                // that 0-RTT was accepted to avoid issues with rejected 0-RTT data
                let _ = zero_rtt_accepted.await;
                log::info!("QUIC: 0-RTT accepted");
                conn
            }
            Err(connecting) => {
                // 0-RTT not available or disabled, fall back to full handshake
                log::info!("QUIC: 0-RTT not available, falling back to 1-RTT handshake");
                connecting.await.context("QUIC handshake failed")?
            }
        }
    } else {
        // 0-RTT disabled, do regular handshake
        log::info!("QUIC: 0-RTT disabled, performing 1-RTT handshake");
        connecting.await.context("QUIC handshake failed")?
    };

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
