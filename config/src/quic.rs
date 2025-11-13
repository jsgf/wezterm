use crate::config::validate_domain_name;
use crate::*;
use wezterm_dynamic::{FromDynamic, ToDynamic};

#[derive(Default, Debug, Clone, FromDynamic, ToDynamic)]
pub struct QuicDomainServer {
    /// The address:port combination on which the server will listen
    /// for client connections
    pub bind_address: String,

    /// Ephemeral certificate lifetime in days (default 7)
    #[dynamic(default = "default_certificate_lifetime_days")]
    pub certificate_lifetime_days: u32,

    /// the path to an x509 PEM encoded private key file
    pub pem_private_key: Option<PathBuf>,

    /// the path to an x509 PEM encoded certificate file
    pub pem_cert: Option<PathBuf>,

    /// the path to an x509 PEM encoded CA chain file
    pub pem_ca: Option<PathBuf>,

    /// A set of paths to load additional CA certificates.
    /// Each entry can be either the path to a directory
    /// or to a PEM encoded CA file.  If an entry is a directory,
    /// then its contents will be loaded as CA certs and added
    /// to the trust store.
    #[dynamic(default)]
    pub pem_root_certs: Vec<PathBuf>,

    /// Maximum idle timeout for QUIC connections
    #[dynamic(default = "default_max_idle_timeout")]
    pub max_idle_timeout: Duration,
}

#[derive(Default, Debug, Clone, FromDynamic, ToDynamic)]
pub struct QuicDomainClient {
    /// The name of this specific domain.  Must be unique amongst
    /// all types of domain in the configuration file.
    #[dynamic(validate = "validate_domain_name")]
    pub name: String,

    /// If set, use ssh to connect, start the server, and obtain
    /// a certificate.
    /// The value is "user@host:port", just like "wezterm ssh" accepts.
    pub bootstrap_via_ssh: Option<String>,

    /// identifies the host:port pair of the remote server.
    pub remote_address: String,

    /// Whether to persist QUIC certificates to disk (default: false)
    /// By default, certificates are kept only in memory for improved security.
    #[dynamic(default)]
    pub persist_to_disk: bool,

    /// Certificate lifetime in days (default 7)
    #[dynamic(default = "default_certificate_lifetime_days")]
    pub certificate_lifetime_days: u32,

    /// Enable 0-RTT mode for faster reconnections (default: true)
    #[dynamic(default = "default_true")]
    pub enable_0rtt: bool,

    /// Enable connection migration (default: true)
    #[dynamic(default = "default_true")]
    pub enable_migration: bool,

    /// Maximum idle timeout for QUIC connections
    #[dynamic(default = "default_max_idle_timeout")]
    pub max_idle_timeout: Duration,

    /// the path to an x509 PEM encoded private key file
    pub pem_private_key: Option<PathBuf>,

    /// the path to an x509 PEM encoded certificate file
    pub pem_cert: Option<PathBuf>,

    /// the path to an x509 PEM encoded CA chain file
    pub pem_ca: Option<PathBuf>,

    /// A set of paths to load additional CA certificates.
    /// Each entry can be either the path to a directory or to a PEM encoded
    /// CA file.  If an entry is a directory, then its contents will be
    /// loaded as CA certs and added to the trust store.
    #[dynamic(default)]
    pub pem_root_certs: Vec<PathBuf>,

    /// explicitly control whether the client checks that the certificate
    /// presented by the server matches the hostname portion of
    /// `remote_address`.  The default is false for QUIC (since we use
    /// self-signed certs exchanged via SSH).  This option is made
    /// available for troubleshooting purposes and should not be used outside
    /// of a controlled environment as it weakens the security of the QUIC
    /// channel.
    #[dynamic(default)]
    pub accept_invalid_hostnames: bool,

    /// the hostname string that we expect to match against the common name
    /// field in the certificate presented by the server.  This defaults to
    /// the hostname portion of the `remote_address` configuration and you
    /// should not normally need to override this value.
    pub expected_cn: Option<String>,

    /// Keep-alive interval for QUIC connections
    pub keep_alive_interval: Option<Duration>,

    /// If true, connect to this domain automatically at startup
    #[dynamic(default)]
    pub connect_automatically: bool,

    #[dynamic(default = "default_read_timeout")]
    pub read_timeout: Duration,

    #[dynamic(default = "default_write_timeout")]
    pub write_timeout: Duration,

    #[dynamic(default = "default_local_echo_threshold_ms")]
    pub local_echo_threshold_ms: Option<u64>,

    /// The path to the wezterm binary on the remote host
    pub remote_wezterm_path: Option<String>,

    /// Show time since last response when waiting for a response.
    /// It is recommended to use
    /// <https://wezterm.org/config/lua/pane/get_metadata.html#since_last_response_ms>
    /// instead.
    #[dynamic(default)]
    pub overlay_lag_indicator: bool,
}

impl QuicDomainClient {
    pub fn ssh_parameters(&self) -> Option<anyhow::Result<SshParameters>> {
        self.bootstrap_via_ssh
            .as_ref()
            .map(|user_at_host_and_port| user_at_host_and_port.parse())
    }
}

fn default_certificate_lifetime_days() -> u32 {
    7
}

fn default_max_idle_timeout() -> Duration {
    Duration::from_secs(30)
}
