// QUIC server implementation
// Handles QUIC endpoint setup and connection acceptance

use anyhow::Context;
use codec::{DecodedPdu, Pdu, StreamPeek};
use config::QuicDomainServer;
use futures::FutureExt;
use mux::{Mux, MuxNotification};
use quinn::rustls;
use smol::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use std::convert::TryFrom;
use std::io::{Cursor, Read};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

#[cfg(feature = "quic")]
use x509_parser::prelude::*;

/// Wraps QUIC streams to implement AsyncRead/AsyncWrite
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
        // Use futures_lite::io::AsyncRead trait (imported at top)
        match Pin::new(&mut self.recv).poll_read(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => {
                log::debug!("QUIC recv error: {:?}", e);
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("QUIC read error: {:?}", e),
                )))
            }
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
        // Use futures_lite::io::AsyncWrite trait (imported at top)
        match Pin::new(&mut self.send).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
            Poll::Ready(Err(e)) => {
                log::debug!("QUIC send error: {:?}", e);
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("QUIC write error: {:?}", e),
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        log::debug!("QUIC poll_close called");
        match self.send.finish() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "QUIC send stream already closed or in error state",
            ))),
        }
    }
}

#[derive(Debug)]
enum Item {
    Response(DecodedPdu),
    Notification(MuxNotification),
}

/// Process a QUIC stream for mux protocol
/// Uses futures::select! for fair concurrent handling of responses and requests
pub async fn process_quic_stream(stream: QuicStream) -> anyhow::Result<()> {
    use smol::channel::unbounded;
    use wezterm_mux_server_impl::sessionhandler::{PduSender, SessionHandler};

    log::debug!("QUIC: process_quic_stream starting");

    let mut stream = StreamPeek::new(stream);

    let (item_tx, item_rx) = unbounded::<Item>();

    let pdu_sender = PduSender::new({
        let item_tx = item_tx.clone();
        move |pdu| {
            item_tx
                .try_send(Item::Response(pdu))
                .map_err(|e| anyhow::anyhow!("{:?}", e))
        }
    });
    let mut handler = SessionHandler::new(pdu_sender);

    // Subscribe to mux notifications (same as dispatch.rs)
    {
        let mux = Mux::get();
        let tx = item_tx.clone();
        mux.subscribe(move |n| tx.try_send(Item::Notification(n)).is_ok());
    }

    loop {
        futures::select! {
            item = item_rx.recv().fuse() => {
                match item {
                    Ok(Item::Response(response_pdu)) => {
                        log::debug!("QUIC: sending response PDU with serial {}", response_pdu.serial);
                        response_pdu.pdu.encode_async(&mut stream, response_pdu.serial).await?;
                        stream.flush().await.context("flushing response PDU to client")?;
                    }
                    Ok(Item::Notification(MuxNotification::PaneOutput(pane_id))) => {
                        log::debug!("QUIC: received PaneOutput notification for pane {}, scheduling push", pane_id);
                        handler.schedule_pane_push(pane_id);
                    }
                    Ok(Item::Notification(_)) => {
                        // Ignore other notifications
                    }
                    Err(_) => {
                        log::debug!("QUIC: stream closed");
                        break;
                    }
                }
            }
            _ = stream.peek().fuse() => {
                // Stream has data available, decode atomically
                match Pdu::decode_async(&mut stream, None).await {
                    Ok(request_pdu) => {
                        log::trace!("QUIC: received PDU from stream: {:?}", request_pdu);
                        handler.process_one(request_pdu);
                    }
                    Err(_) => {
                        log::debug!("QUIC: stream closed (EOF or error)");
                        break;
                    }
                }
            }
        }
    }

    log::debug!("QUIC: stream processing complete");
    Ok(())
}

/// Extract CN (Common Name) from a certificate
/// Returns the CN value if found, None otherwise
#[cfg(feature = "quic")]
fn extract_cn_from_certificate(cert_der: &rustls::pki_types::CertificateDer<'_>) -> anyhow::Result<String> {
    let (_remainder, parsed) = parse_x509_certificate(cert_der.as_ref())
        .context("Failed to parse X.509 certificate")?;

    let subject = &parsed.tbs_certificate.subject;

    // Look for CommonName attribute in the subject DN
    for rdn in subject.iter_common_name() {
        if let Ok(cn) = rdn.as_str() {
            return Ok(cn.to_string());
        }
    }

    Err(anyhow::anyhow!("Certificate has no CommonName (CN) attribute"))
}

/// Validate that client certificate CN matches expected user
/// Accepts both direct match (CN == username) and prefixed format (user:username/)
#[cfg(feature = "quic")]
fn validate_client_cn(cn: &str, expected_user: &str) -> anyhow::Result<()> {
    // Direct match: CN == username
    if cn == expected_user {
        log::trace!(
            "QUIC: Client certificate CN `{}` matches $USER `{}`",
            cn,
            expected_user
        );
        return Ok(());
    }

    // Prefixed format: CN starts with "user:<username>/"
    let prefix = format!("user:{}/", expected_user);
    if cn.starts_with(&prefix) {
        log::trace!(
            "QUIC: Client certificate CN `{}` matches $USER `{}` (prefixed format)",
            cn,
            expected_user
        );
        return Ok(());
    }

    anyhow::bail!(
        "QUIC: Client certificate CN `{}` does not match $USER `{}`",
        cn,
        expected_user
    );
}

/// Verify client certificate CN when client certificate verification is enabled
/// This is called after the TLS handshake when a client certificate is present
#[cfg(feature = "quic")]
fn verify_client_certificate_cn(connection: &quinn::Connection) -> anyhow::Result<()> {
    // Get peer identity (client certificates)
    let peer_identity = connection
        .peer_identity()
        .ok_or_else(|| anyhow::anyhow!("QUIC: No peer identity available"))?;

    // Cast to Vec<CertificateDer>
    let certs = peer_identity
        .downcast_ref::<Vec<rustls::pki_types::CertificateDer<'_>>>()
        .ok_or_else(|| anyhow::anyhow!("QUIC: Failed to downcast peer identity to certificates"))?;

    // Get the client certificate (first one in chain)
    let client_cert = certs
        .first()
        .ok_or_else(|| anyhow::anyhow!("QUIC: Peer identity contains no certificates"))?;

    // Extract CN from client certificate
    let cn = extract_cn_from_certificate(client_cert)
        .context("QUIC: Failed to extract CN from client certificate")?;

    // Get expected username from environment
    let expected_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .context("QUIC: Failed to get $USER or $USERNAME environment variable")?;

    // Validate CN matches expected user
    validate_client_cn(&cn, &expected_user)
        .context("QUIC: Client certificate CN validation failed")?;

    Ok(())
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

/// Spawn a QUIC listener for the given configuration
/// Like TLS, we run this in a separate thread with its own smol::block_on executor
/// This avoids executor incompatibility with async-executor used by promise::spawn
pub fn spawn_quic_listener(quic_server: &QuicDomainServer) -> anyhow::Result<()> {
    let quic_server = quic_server.clone();

    std::thread::spawn(move || {
        smol::block_on(async {
            if let Err(e) = run_quic_listener(&quic_server).await {
                log::error!("QUIC listener error: {}", e);
            }
        })
    });

    Ok(())
}

async fn run_quic_listener(quic_server: &QuicDomainServer) -> anyhow::Result<()> {
    let listen_addr: std::net::SocketAddr = quic_server.bind_address.parse()?;

    log::debug!(
        "QUIC: Generating server certificate with {} day lifetime",
        quic_server.certificate_lifetime_days
    );

    let pki = &wezterm_mux_server_impl::PKI;
    let extra_san = if quic_server.extra_san.is_empty() {
        None
    } else {
        log::debug!("QUIC: Adding extra SANs to certificate: {:?}", quic_server.extra_san);
        Some(quic_server.extra_san.clone())
    };

    let cert_data = pki
        .generate_server_cert(quic_server.certificate_lifetime_days, extra_san)
        .context("Failed to generate server certificate")?;

    // Parse PEM into rustls format
    let cert_chain: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_data))
            .collect::<Result<Vec<_>, _>>()
            .context("parsing server certificate")?;

    // Extract private key from PEM
    let server_key = wezterm_mux_server_impl::pki::extract_private_key_from_bytes(cert_data.as_bytes())?;

    // Load client CA for verification if configured
    // Priority: explicit CA > ephemeral PKI CA (if using ephemeral PKI)
    let server_config = if let Some(ca_path) = &quic_server.pem_ca {
        // Explicit CA configured
        log::debug!("QUIC: Verifying client certificates against CA: {}", ca_path.display());
        let client_ca_certs = load_certificates_from_file(ca_path)
            .context("Failed to load client CA certificate")?;

        let mut roots = rustls::RootCertStore::empty();
        for cert in client_ca_certs {
            roots.add(cert)
                .context("Failed to add client CA certificate to root store")?;
        }

        rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .context("Failed to build client cert verifier")?,
            )
            .with_single_cert(cert_chain, server_key)
            .context("building server config with client cert verification")?
    } else if !quic_server.pem_root_certs.is_empty() {
        // Load additional CAs for client verification
        log::debug!(
            "QUIC: Verifying client certificates against {} root CA(s)",
            quic_server.pem_root_certs.len()
        );
        let mut roots = rustls::RootCertStore::empty();

        for ca_path in &quic_server.pem_root_certs {
            let certs = load_certificates_from_file(ca_path)
                .context("Failed to load root CA certificate")?;
            for cert in certs {
                roots.add(cert)
                    .context("Failed to add root CA certificate")?;
            }
        }

        rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .context("Failed to build client cert verifier")?,
            )
            .with_single_cert(cert_chain, server_key)
            .context("building server config with client cert verification")?
    } else if let Ok(ca_pem) = pki.ca_pem_string() {
        // Use ephemeral PKI CA for client verification when using ephemeral certs
        log::debug!("QUIC: Verifying client certificates against ephemeral PKI CA");
        let mut cursor = Cursor::new(ca_pem.as_bytes());
        let ca_certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut cursor)
            .collect::<Result<Vec<_>, _>>()
            .context("Failed to parse ephemeral PKI CA certificate")?;

        let mut roots = rustls::RootCertStore::empty();
        for cert in ca_certs {
            roots.add(cert)
                .context("Failed to add ephemeral PKI CA certificate to root store")?;
        }

        rustls::ServerConfig::builder()
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                    .build()
                    .context("Failed to build client cert verifier")?,
            )
            .with_single_cert(cert_chain, server_key)
            .context("building server config with ephemeral PKI client cert verification")?
    } else {
        // No client CA configured, skip verification
        log::debug!("QUIC: No client CA configured, skipping client certificate verification");
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, server_key)
            .context("building server config")?
    };

    // Create Quinn ServerConfig from rustls
    let quinn_crypto_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
        .context("converting to QUIC config")?;
    let mut quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_crypto_config));

    // Apply transport configuration from config
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(quic_server.max_idle_timeout)
            .context("Invalid max_idle_timeout")?,
    ));
    quinn_config.transport_config(Arc::new(transport));

    // Bind UDP socket
    let socket = std::net::UdpSocket::bind(listen_addr).context("binding UDP socket")?;
    socket
        .set_nonblocking(true)
        .context("setting socket to non-blocking")?;

    // Create Quinn endpoint with SmolRuntime
    // This runs in its own thread with its own executor, so no incompatibility with async-executor
    let runtime = Arc::new(quinn::SmolRuntime);
    let endpoint = quinn::Endpoint::new(Default::default(), Some(quinn_config), socket, runtime)
        .context("creating QUIC endpoint")?;

    log::debug!("QUIC server successfully created endpoint and listening on {}", listen_addr);

    // Run the accept loop in this thread's smol executor
    log::debug!("QUIC: Starting main accept loop");
    loop {
        log::debug!("QUIC: Waiting for new connection with endpoint.accept().await");
        match endpoint.accept().await {
            Some(connecting) => {
                log::debug!("QUIC: Got Connecting, waiting for handshake completion");
                let connection = match connecting.await {
                    Ok(conn) => {
                        log::debug!("QUIC: Handshake completed successfully");
                        conn
                    }
                    Err(e) => {
                        log::error!("QUIC handshake failed: {}", e);
                        continue;
                    }
                };

                let peer_addr = connection.remote_address();
                log::info!("QUIC connection from {}", peer_addr);

                // Verify client certificate CN if client certs are being validated
                #[cfg(feature = "quic")]
                if connection.peer_identity().is_some() {
                    if let Err(e) = verify_client_certificate_cn(&connection) {
                        log::error!("QUIC: Client CN validation failed for {}: {}", peer_addr, e);
                        // Close the connection on CN validation failure
                        connection.close(1u32.into(), b"CN validation failed");
                        continue;
                    }
                    log::debug!("QUIC: Client CN validation successful for {}", peer_addr);
                }

                // Spawn connection handler in smol executor (we're in a separate thread with smol::block_on)
                log::debug!("QUIC: Spawning connection handler for {}", peer_addr);
                smol::spawn(async move {
                    log::debug!("QUIC: Connection handler task started for {}", peer_addr);
                    loop {
                        log::debug!("QUIC: Waiting for stream from {} with accept_bi().await", peer_addr);
                        match connection.accept_bi().await {
                            Ok((send, recv)) => {
                                log::debug!("Accepted QUIC stream from {}", peer_addr);
                                let stream = QuicStream::new(send, recv);

                                // Process each stream in-place (sequential per connection)
                                log::debug!("QUIC: Processing stream from {}", peer_addr);
                                if let Err(e) = process_quic_stream(stream).await {
                                    log::error!("QUIC stream error: {}", e);
                                }
                                log::debug!("QUIC: Stream processing complete for {}", peer_addr);
                            }
                            Err(e) => {
                                log::debug!("No more streams from {}: {}", peer_addr, e);
                                break;
                            }
                        }
                    }
                    log::debug!("QUIC: Connection handler task ending for {}", peer_addr);
                })
                .detach();
                log::debug!("QUIC: Connection handler spawned for {}", peer_addr);
            }
            None => {
                log::debug!("QUIC endpoint closed");
                break;
            }
        }
    }

    Ok(())
}
