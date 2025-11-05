// QUIC client implementation - basic scaffold
// Phase 2 implementation: basic connection establishment

#![cfg(feature = "quic")]

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use quinn::{ClientConfig, Endpoint, EndpointConfig};
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

/// QUIC stream wrapper that implements AsyncReadAndWrite
#[derive(Debug)]
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    /// Connect to a QUIC server and establish a bidirectional stream
    pub async fn connect(remote_address: &str) -> Result<Self> {
        // Parse address
        let socket_addr: SocketAddr = remote_address
            .parse()
            .map_err(|_| anyhow!("Invalid address: {}", remote_address))?;

        // Create client config with insecure certificate verification for now
        // (will be replaced with proper validation when SSH bootstrap is added)
        let client_config = create_client_config()?;

        // Create endpoint
        let endpoint = Endpoint::new(
            EndpointConfig::default(),
            Some(client_config),
            quinn::default_runtime()
                .ok_or_else(|| anyhow!("No async runtime available"))?,
        )?;

        // Connect to server
        let connection = endpoint
            .connect(socket_addr, "localhost")?
            .await
            .map_err(|e| anyhow!("QUIC connection failed: {}", e))?;

        // Open bidirectional stream
        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| anyhow!("Failed to open QUIC stream: {}", e))?;

        Ok(Self { send, recv })
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        // This is a synchronous API, but we need to be async
        // For now, return would-block to avoid blocking
        // In a full implementation, this would properly integrate with the async runtime
        Poll::Pending
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[async_trait]
impl crate::client::AsyncReadAndWrite for QuicStream {
    async fn wait_for_readable(&self) -> Result<()> {
        // For QUIC, we'll just return ready
        // In a full implementation, this would wait for data availability
        Ok(())
    }
}

/// Create a basic client config with insecure certificate verification
/// TODO: Replace with proper certificate validation when SSH bootstrap is implemented
fn create_client_config() -> Result<ClientConfig> {
    // Create a rustls client config that skips verification
    // This is only safe for the initial scaffold; real implementation will verify
    // certificates through SSH bootstrap
    let root_store = rustls::RootCertStore::empty();

    let rustls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let client_config = ClientConfig::new(std::sync::Arc::new(rustls_config));

    Ok(client_config)
}
