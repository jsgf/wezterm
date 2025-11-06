// QUIC server implementation
// Handles QUIC endpoint setup and connection acceptance

use anyhow::{anyhow, Context};
use codec::{DecodedPdu, Pdu};
use config::QuicDomainServer;
use promise::spawn::spawn_into_main_thread;
use quinn::rustls;
use smol::io::{AsyncRead, AsyncWrite};
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
        // Use futures_lite::io::AsyncWrite trait (imported at top)
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
        Poll::Ready(Ok(()))
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        _cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.send.finish() {
            Ok(()) => Poll::Ready(Ok(())),
            Err(_e) => Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "QUIC send stream already closed or in error state",
            ))),
        }
    }
}

/// Process a QUIC stream for mux protocol
/// This is a simplified version that handles the mux protocol without
/// relying on the file descriptor-based dispatch system
pub async fn process_quic_stream(mut stream: QuicStream) -> anyhow::Result<()> {
    use smol::channel::unbounded;
    use wezterm_mux_server_impl::sessionhandler::{PduSender, SessionHandler};

    log::debug!("Processing QUIC stream");

    let (item_tx, item_rx) = unbounded::<DecodedPdu>();

    let pdu_sender = PduSender::new({
        let item_tx = item_tx.clone();
        move |pdu| {
            item_tx
                .try_send(pdu)
                .map_err(|e| anyhow::anyhow!("{:?}", e))
        }
    });
    let mut handler = SessionHandler::new(pdu_sender);

    loop {
        // Try to receive messages or read from stream
        match smol::future::or(async { item_rx.recv().await.ok() }, async {
            Pdu::decode_async(&mut stream, None).await.ok()
        })
        .await
        {
            Some(decoded) => {
                handler.process_one(decoded);
            }
            None => {
                // EOF or error
                break;
            }
        }
    }

    Ok(())
}

/// Spawn a QUIC listener for the given configuration
pub fn spawn_quic_listener(quic_server: &QuicDomainServer) -> anyhow::Result<()> {
    // Parse bind address
    let listen_addr: std::net::SocketAddr = quic_server
        .bind_address
        .parse()
        .context("Invalid bind address for QUIC server")?;

    log::info!("QUIC server configured to listen on {}", listen_addr);

    // Clone config for the thread
    let quic_server = quic_server.clone();

    std::thread::spawn(move || {
        if let Err(e) = run_quic_listener(&quic_server) {
            log::error!("QUIC listener error: {}", e);
        }
    });

    Ok(())
}

fn run_quic_listener(quic_server: &QuicDomainServer) -> anyhow::Result<()> {
    let listen_addr: std::net::SocketAddr = quic_server.bind_address.parse()?;

    // Initialize PKI with configured certificate lifetime
    let pki = wezterm_mux_server_impl::pki::Pki::init_with_lifetime(
        quic_server.certificate_lifetime_days,
    )?;

    // Load server certificate and key
    let cert_path = pki.server_pem();
    let ca_path = pki.ca_pem();

    let cert_data = std::fs::read(&cert_path)
        .context(format!("reading server cert from {}", cert_path.display()))?;
    let ca_data =
        std::fs::read(&ca_path).context(format!("reading CA cert from {}", ca_path.display()))?;

    // Parse PEM into rustls format
    let cert_chain: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_data))
            .collect::<Result<Vec<_>, _>>()
            .context("parsing server certificate")?;

    let mut key_reader = std::io::Cursor::new(&cert_data);
    let key_bytes = rustls_pemfile::read_one(&mut key_reader)
        .context("reading server key")?
        .ok_or_else(|| anyhow!("no private key found in PEM"))?;

    let server_key = match key_bytes {
        rustls_pemfile::Item::Pkcs8Key(key) => rustls::pki_types::PrivateKeyDer::Pkcs8(key),
        rustls_pemfile::Item::Sec1Key(key) => rustls::pki_types::PrivateKeyDer::Sec1(key),
        _ => anyhow::bail!("unsupported key type in PEM (expected PKCS8 or SEC1)"),
    };

    // Load CA certificate for client verification
    let ca_certs: Vec<rustls::pki_types::CertificateDer> =
        rustls_pemfile::certs(&mut std::io::Cursor::new(&ca_data))
            .collect::<Result<Vec<_>, _>>()
            .context("parsing CA certificate")?;

    let mut ca_store = rustls::RootCertStore::empty();
    for cert in ca_certs {
        ca_store.add(cert).context("adding CA cert to store")?;
    }

    // Build rustls ServerConfig with client cert verification
    let server_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(
            rustls::server::WebPkiClientVerifier::builder(Arc::new(ca_store))
                .build()
                .context("building client verifier")?,
        )
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

    // Create Quinn endpoint with smol runtime
    let runtime = quinn::default_runtime().ok_or_else(|| anyhow!("no async runtime available"))?;

    let endpoint = quinn::Endpoint::new(Default::default(), Some(quinn_config), socket, runtime)
        .context("creating QUIC endpoint")?;

    log::info!("QUIC server listening on {}", listen_addr);

    // Run the accept loop in smol context
    smol::block_on(async {
        loop {
            match endpoint.accept().await {
                Some(connecting) => {
                    let connection = match connecting.await {
                        Ok(conn) => conn,
                        Err(e) => {
                            log::error!("QUIC handshake failed: {}", e);
                            continue;
                        }
                    };

                    let peer_addr = connection.remote_address();
                    log::debug!("QUIC connection from {}", peer_addr);

                    // Spawn stream handler
                    let _handle = smol::spawn(async move {
                        match connection.accept_bi().await {
                            Ok((send, recv)) => {
                                let stream = QuicStream::new(send, recv);

                                // Dispatch to main thread for mux processing
                                spawn_into_main_thread(async move {
                                    if let Err(e) = process_quic_stream(stream).await {
                                        log::error!("QUIC stream error: {}", e);
                                    }
                                })
                                .detach();
                            }
                            Err(e) => {
                                log::error!(
                                    "Failed to accept QUIC stream from {}: {}",
                                    peer_addr,
                                    e
                                );
                            }
                        }
                    });
                }
                None => {
                    log::info!("QUIC endpoint closed");
                    break;
                }
            }
        }
    });

    Ok(())
}
