// QUIC server implementation - basic scaffold
// Phase 3 implementation: server endpoint and connection handling

use anyhow::bail;
use config::QuicDomainServer;

/// Spawn a QUIC listener for the given configuration
pub async fn spawn_quic_listener(_quic_server: &QuicDomainServer) -> anyhow::Result<()> {
    bail!("QUIC server implementation pending - requires quinn endpoint setup and connection handling");
}
