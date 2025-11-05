use crate::client::Client;
use anyhow::bail;
use config::QuicDomainClient;
use mux::connui::ConnectionUI;
use mux::domain::DomainId;

impl Client {
    pub fn new_quic(
        _domain_id: DomainId,
        _quic_client: &QuicDomainClient,
        _ui: &mut ConnectionUI,
    ) -> anyhow::Result<Self> {
        bail!("QUIC transport is not yet fully implemented");
    }
}
