use clap::Parser;
use wezterm_client::client::Client;

#[derive(Debug, Parser, Clone)]
pub struct QuicCredsCommand {
    /// Output a PEM file encoded copy of the credentials.
    ///
    /// They will be valid for the lifetime of the mux server
    /// process.
    ///
    /// Take care with them, as anyone with them will be able
    /// to connect directly to your mux server via the network
    /// and start a shell with no additional authentication.
    #[clap(long)]
    pem: bool,
}

impl QuicCredsCommand {
    pub async fn run(self, _client: Client) -> anyhow::Result<()> {
        anyhow::bail!("QUIC credentials command not yet implemented");
    }
}
