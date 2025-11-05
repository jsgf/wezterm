# QuicDomainClient

The `QuicDomainClient` struct specifies information about how to connect
to a [QUIC Domain](../../multiplexing.md#quic-domains).

It is a lua object with the following fields:

```lua
config.quic_clients = {
  {
    -- The name of this specific domain.  Must be unique amongst
    -- all types of domain in the configuration file.
    name = 'server.name',

    -- If set, use ssh to connect, start the server, and obtain
    -- a certificate.
    -- The value is "user@host:port", just like "wezterm ssh" accepts.
    bootstrap_via_ssh = 'server.hostname',

    -- identifies the host:port pair of the remote server.
    remote_address = 'server.hostname:9001',

    -- Whether to persist QUIC certificates to disk (default: false).
    -- By default, certificates are kept only in memory for improved security.
    persist_to_disk = false,

    -- Certificate lifetime in days (default: 7).
    -- Certificates are automatically renewed before expiry.
    certificate_lifetime_days = 7,

    -- Enable 0-RTT mode for faster reconnections (default: true)
    enable_0rtt = true,

    -- Enable connection migration for network changes (default: true).
    -- Allows seamless reconnection when network changes (WiFi to Ethernet, etc.)
    enable_migration = true,

    -- Maximum idle timeout for QUIC connections (default: 30 seconds)
    -- max_idle_timeout = 30,

    -- the path to an x509 PEM encoded private key file.
    -- Omit this if you are using `bootstrap_via_ssh`.
    -- pem_private_key = "/some/path/key.pem",

    -- the path to an x509 PEM encoded certificate file
    -- Omit this if you are using `bootstrap_via_ssh`.
    -- pem_cert = "/some/path/cert.pem",

    -- the path to an x509 PEM encoded CA chain file
    -- Omit this if you are using `bootstrap_via_ssh`.
    -- pem_ca = "/some/path/ca.pem",

    -- A set of paths to load additional CA certificates.
    -- Each entry can be either the path to a directory or to a PEM encoded
    -- CA file.  If an entry is a directory, then its contents will be
    -- loaded as CA certs and added to the trust store.
    -- Omit this if you are using `bootstrap_via_ssh`.
    -- pem_root_certs = { "/some/path/ca1.pem", "/some/path/ca2.pem" },

    -- explicitly control whether the client checks that the certificate
    -- presented by the server matches the hostname portion of
    -- `remote_address`.  The default is false for QUIC (since we use
    -- self-signed certs exchanged via SSH).  This option is made
    -- available for troubleshooting purposes and should not be used outside
    -- of a controlled environment as it weakens the security of the QUIC
    -- channel.
    -- accept_invalid_hostnames = false,

    -- the hostname string that we expect to match against the common name
    -- field in the certificate presented by the server.  This defaults to
    -- the hostname portion of the `remote_address` configuration and you
    -- should not normally need to override this value.
    -- expected_cn = "other.name",

    -- If true, connect to this domain automatically at startup
    -- connect_automatically = false,

    -- Specify an alternate read timeout (in seconds)
    -- read_timeout = 60,

    -- Specify an alternate write timeout (in seconds)
    -- write_timeout = 60,

    -- The path to the wezterm binary on the remote host
    -- remote_wezterm_path = "/home/myname/bin/wezterm",

    -- Show time since last response when waiting for a response.
    -- It is recommended to use
    -- [get_metadata](pane/get_metadata.md#since_last_response_ms)
    -- instead.
    -- overlay_lag_indicator = false,
  },
}
```

## Certificate Management

QUIC domains automatically manage certificates for you:

- **Initial Connection**: The first connection uses SSH to bootstrap and exchange
  self-signed certificates
- **In-Memory Storage**: By default, certificates are kept in memory only
  (more secure, but won't persist across wezterm restarts)
- **Disk Persistence**: Set `persist_to_disk = true` to save certificates to
  `~/.local/share/wezterm/pki/{domain}/` for debugging or compliance purposes
- **Automatic Renewal**: Certificates are automatically renewed in the background
  before expiry (at ~80% of lifetime)
- **Graceful Fallback**: If a certificate expires, the client will automatically
  re-bootstrap via SSH on the next connection

## Certificate Lifetime

The `certificate_lifetime_days` option controls how long generated certificates
are valid. The default is 7 days. Shorter lifetimes provide better security by
limiting the window of exposure if a certificate is compromised, but require
more frequent renewal.

## Network Resilience

When `enable_migration` is true (the default), QUIC connections automatically
adapt to network changes:

- Seamlessly switches between networks (WiFi to Ethernet, etc.)
- Survives IP address changes on the same network
- Maintains connection state across migrations

This is particularly useful for mobile or unstable network environments.

## Performance

QUIC domains are typically much faster than TLS domains for reconnections:

- **Initial connection**: ~100-500ms (same as TLS, due to SSH bootstrap)
- **Reconnection**: < 10ms (0-RTT, cached with certificate)
- **Network migration**: Transparent and automatic

## See Also

- [Multiplexing Documentation](../../multiplexing.md#quic-domains)
- [QUIC Protocol](https://en.wikipedia.org/wiki/QUIC)
