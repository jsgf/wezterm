use anyhow::bail;
use config::QuicDomainServer;

/// Spawn a QUIC listener for the given configuration
pub fn spawn_quic_listener(_quic_server: &QuicDomainServer) -> anyhow::Result<()> {
    #[cfg(feature = "quic")]
    {
        // TODO: Implement QUIC server listener
        // This is a placeholder for Phase 3 implementation
        Ok(())
    }
    #[cfg(not(feature = "quic"))]
    {
        log::error!("QUIC support is not compiled in. Rebuild wezterm with: cargo build --features quic");
        bail!("QUIC support is not compiled in. Rebuild wezterm with: cargo build --features quic");
    }
}
