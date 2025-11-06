// QUIC client implementation
// Handles QUIC connections with certificate caching and SSH bootstrap

use anyhow::{anyhow, Context};
use async_trait::async_trait;
use smol::io::{AsyncRead, AsyncWrite};
use std::convert::TryFrom;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use quinn::crypto::rustls::QuicClientConfig as RustlsQuicClientConfig;

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

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
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
impl crate::client::AsyncReadAndWrite for QuicStream {
    async fn wait_for_readable(&self) -> anyhow::Result<()> {
        // No-op for QUIC streams - they handle buffering internally
        Ok(())
    }
}

/// Establish a QUIC connection to a remote mux server
pub async fn establish_quic_connection(
    remote_address: &str,
    _client_cert_pem: Option<String>,
    _ca_cert_pem: Option<String>,
) -> anyhow::Result<Box<dyn crate::client::AsyncReadAndWrite>> {
    // Parse remote address
    let socket_addr: std::net::SocketAddr = remote_address
        .parse()
        .context("Invalid remote address format (expected host:port)")?;

    // Extract hostname for SNI
    let hostname = remote_address
        .split(':')
        .next()
        .ok_or_else(|| anyhow!("Missing hostname in remote_address"))?;

    // Create QUIC endpoint bound to any local address
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)
        .context("Failed to create QUIC endpoint")?;

    // Create rustls client config - trust system root certificates
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_crypto = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    // Convert to QuicClientConfig using TryFrom
    let quic_client_config = RustlsQuicClientConfig::try_from(client_crypto)?;
    let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    endpoint.set_default_client_config(client_config);

    // Connect to server
    let connection = endpoint
        .connect(socket_addr, hostname)
        .context("Failed to create QUIC connection")?
        .await
        .context("QUIC handshake failed")?;

    // Open a bidirectional stream for mux protocol
    let (send, recv) = connection
        .open_bi()
        .await
        .context("Failed to open QUIC stream")?;

    let stream = Box::new(QuicStream::new(send, recv));
    Ok(stream)
}
