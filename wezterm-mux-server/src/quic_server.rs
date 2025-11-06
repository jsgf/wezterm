// QUIC server implementation
// Handles QUIC endpoint setup and connection acceptance

use anyhow::{anyhow, Context};
use codec::{Pdu, DecodedPdu};
use config::QuicDomainServer;
use promise::spawn::spawn_into_main_thread;
use std::sync::Arc;
use std::convert::TryFrom;
use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};
use smol::io::{AsyncRead, AsyncWrite};
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

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
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
    use wezterm_mux_server_impl::sessionhandler::{SessionHandler, PduSender};
    use smol::channel::unbounded;

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
        match smol::future::or(
            async { item_rx.recv().await.ok() },
            async { Pdu::decode_async(&mut stream, None).await.ok() },
        )
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
    let bind_address = quic_server.bind_address.clone();
    let cert_lifetime_days = quic_server.certificate_lifetime_days;

    std::thread::spawn(move || {
        if let Err(e) = run_quic_listener(&bind_address, cert_lifetime_days) {
            log::error!("QUIC listener error: {}", e);
        }
    });

    Ok(())
}

fn run_quic_listener(bind_address: &str, cert_lifetime_days: u32) -> anyhow::Result<()> {
    let listen_addr: std::net::SocketAddr = bind_address.parse()?;

    // Initialize PKI with configured certificate lifetime
    let pki = wezterm_mux_server_impl::pki::Pki::init_with_lifetime(cert_lifetime_days)?;

    // Load server certificate and key
    let cert_path = pki.server_pem();
    let ca_path = pki.ca_pem();

    let cert_data = std::fs::read(&cert_path)
        .context(format!("reading server cert from {}", cert_path.display()))?;
    let ca_data = std::fs::read(&ca_path)
        .context(format!("reading CA cert from {}", ca_path.display()))?;

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
        rustls_pemfile::Item::Pkcs8Key(key) => {
            rustls::pki_types::PrivateKeyDer::Pkcs8(key)
        }
        rustls_pemfile::Item::Sec1Key(key) => {
            rustls::pki_types::PrivateKeyDer::Sec1(key)
        }
        #[cfg(feature = "rsa")]
        rustls_pemfile::Item::RsaKey(key) => {
            rustls::pki_types::PrivateKeyDer::Rsa(key)
        }
        _ => anyhow::bail!("unsupported key type in PEM"),
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
    let quinn_config = quinn::crypto::rustls::QuicServerConfig::try_from(server_config)
        .context("converting to QUIC config")?;
    let quinn_config = quinn::ServerConfig::with_crypto(Arc::new(quinn_config));

    // Note: Full QUIC endpoint implementation requires wrapping quinn's async API
    // with smol runtime. The following is a scaffold that demonstrates the architecture:
    //
    // 1. Create quinn::Endpoint with ServerConfig and bound UDP socket
    // 2. Accept connections in accept() loop
    // 3. For each connection, accept bidirectional streams
    // 4. Wrap each stream in QuicStream (which implements AsyncRead/AsyncWrite)
    // 5. Process via process_quic_stream which handles mux protocol PDUs
    //
    // Current limitation: quinn's Endpoint requires specific async runtime setup.
    // Needs integration with smol's runtime and proper AsyncUdpSocket wrapping.

    log::warn!("QUIC server: {} - architecture implemented, endpoint binding needs quinn async integration", listen_addr);
    log::warn!("QUIC server scaffold complete with:");
    log::warn!("  - Certificate loading and validation");
    log::warn!("  - QuicStream wrapper (AsyncRead+AsyncWrite)");
    log::warn!("  - PDU handler (process_quic_stream)");
    log::warn!("  - TLS config from rustls");

    // For now, just initialize PKI and exit
    // In a full implementation, this would spawn the actual listener
    Ok(())
}
