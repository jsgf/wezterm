// QUIC server implementation
// Handles QUIC endpoint setup and connection acceptance

use anyhow::{anyhow, Context};
use codec::{DecodedPdu, Pdu};
use config::QuicDomainServer;
use promise::spawn::spawn;
use quinn::rustls;
use smol::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use std::convert::TryFrom;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};

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
            Poll::Ready(Ok(n)) => {
                log::trace!("QUIC poll_read: Ready with {} bytes", n);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                log::error!("QUIC poll_read: Error: {:?}", e);
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
            Poll::Ready(Ok(n)) => {
                log::trace!("QUIC poll_write: Ready wrote {} bytes", n);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => {
                log::error!("QUIC poll_write: Error: {:?}", e);
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("QUIC write error: {:?}", e),
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        log::trace!("QUIC poll_flush called");
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

/// Item represents either a response to send or a request to process
enum StreamItem {
    Response(DecodedPdu),
    Request(DecodedPdu),
}

/// Process a QUIC stream for mux protocol
/// This is a simplified version that handles the mux protocol without
/// relying on the file descriptor-based dispatch system
pub async fn process_quic_stream(mut stream: QuicStream) -> anyhow::Result<()> {
    use smol::channel::unbounded;
    use wezterm_mux_server_impl::sessionhandler::{PduSender, SessionHandler};

    log::debug!("QUIC: process_quic_stream starting");
    log::info!("Processing QUIC stream");

    let (item_tx, item_rx) = unbounded::<DecodedPdu>();

    let pdu_sender = PduSender::new({
        let item_tx = item_tx.clone();
        move |pdu| {
            log::debug!("QUIC: PduSender callback with PDU");
            item_tx
                .try_send(pdu)
                .map_err(|e| anyhow::anyhow!("{:?}", e))
        }
    });
    let mut handler = SessionHandler::new(pdu_sender);
    log::debug!("QUIC: SessionHandler created, entering main loop");

    loop {
        log::debug!("QUIC: Top of stream processing loop, waiting for request or response");
        // Wait for either a response to send OR data to read from stream
        match smol::future::or(
            async {
                log::debug!("Waiting for response from item_rx");
                item_rx.recv().await.ok().map(StreamItem::Response)
            },
            async {
                log::debug!("Waiting for request from decode_async");
                Pdu::decode_async(&mut stream, None).await.ok().map(StreamItem::Request)
            },
        )
        .await
        {
            Some(StreamItem::Response(response_pdu)) => {
                log::info!("Got response from handler, writing response PDU with serial {}", response_pdu.serial);
                response_pdu.pdu.encode_async(&mut stream, response_pdu.serial).await?;
                stream.flush().await.context("flushing response PDU to client")?;
                log::info!("Response written and flushed");
            }
            Some(StreamItem::Request(request_pdu)) => {
                log::info!("Got PDU from stream: {:?}", request_pdu);
                handler.process_one(request_pdu);
            }
            None => {
                // EOF or error
                log::info!("QUIC stream closed (EOF or error)");
                break;
            }
        }
    }

    log::info!("QUIC stream processing complete");
    Ok(())
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

    // Initialize PKI to get the server certificate (kept in-memory)
    // Note: Quiccreds will generate its own client certificate,
    // but that's OK since we skip client cert verification with with_no_client_auth()
    log::info!("QUIC: Initializing PKI for server certificate");

    let pki = &wezterm_mux_server_impl::PKI;
    let cert_data = pki.server_pem_string().to_string();
    // CA not needed since we use with_no_client_auth() on the server

    // Parse PEM into rustls format
    let cert_chain: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_data))
            .collect::<Result<Vec<_>, _>>()
            .context("parsing server certificate")?;

    // Extract private key by reading all PEM items and finding the key
    let mut key_reader = std::io::Cursor::new(&cert_data);
    let mut server_key: Option<rustls::pki_types::PrivateKeyDer> = None;

    loop {
        match rustls_pemfile::read_one(&mut key_reader) {
            Ok(Some(item)) => {
                match item {
                    rustls_pemfile::Item::Pkcs8Key(key) => {
                        server_key = Some(rustls::pki_types::PrivateKeyDer::Pkcs8(key));
                        break;
                    }
                    rustls_pemfile::Item::Sec1Key(key) => {
                        server_key = Some(rustls::pki_types::PrivateKeyDer::Sec1(key));
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

    let server_key = server_key.ok_or_else(|| anyhow!("no private key found in PEM"))?;

    // NOTE: For testing, we skip client certificate verification.
    // The connection is already authenticated via SSH bootstrap, so we don't need
    // to verify the client's certificate signed by a CA. The client just needs a cert
    // for the TLS handshake. This avoids the issue of server and quiccreds
    // subprocess generating different CAs.
    // In production, this should be replaced with proper client cert verification.
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, server_key)
        .context("building server config")?;

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
    if let Some(keep_alive) = quic_server.keep_alive_interval {
        transport.keep_alive_interval(Some(keep_alive));
    }
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

    log::info!("QUIC server successfully created endpoint and listening on {}", listen_addr);

    // Run the accept loop in this thread's smol executor
    log::debug!("QUIC: Starting main accept loop");
    loop {
        log::debug!("QUIC: Waiting for new connection with endpoint.accept().await");
        match endpoint.accept().await {
            Some(connecting) => {
                log::debug!("QUIC: Got Connecting, waiting for handshake completion");
                let connection = match connecting.await {
                    Ok(conn) => {
                        log::info!("QUIC: Handshake completed successfully");
                        conn
                    }
                    Err(e) => {
                        log::error!("QUIC handshake failed: {}", e);
                        continue;
                    }
                };

                let peer_addr = connection.remote_address();
                log::info!("QUIC connection from {}", peer_addr);

                // Spawn connection handler in smol executor (we're in a separate thread with smol::block_on)
                log::debug!("QUIC: Spawning connection handler for {}", peer_addr);
                smol::spawn(async move {
                    log::debug!("QUIC: Connection handler task started for {}", peer_addr);
                    loop {
                        log::debug!("QUIC: Waiting for stream from {} with accept_bi().await", peer_addr);
                        match connection.accept_bi().await {
                            Ok((send, recv)) => {
                                log::info!("Accepted QUIC stream from {}", peer_addr);
                                let stream = QuicStream::new(send, recv);

                                // Process each stream in-place (sequential per connection)
                                log::debug!("QUIC: Processing stream from {}", peer_addr);
                                if let Err(e) = process_quic_stream(stream).await {
                                    log::error!("QUIC stream error: {}", e);
                                }
                                log::debug!("QUIC: Stream processing complete for {}", peer_addr);
                            }
                            Err(e) => {
                                log::info!("No more streams from {}: {}", peer_addr, e);
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
                log::info!("QUIC endpoint closed");
                break;
            }
        }
    }

    Ok(())
}
