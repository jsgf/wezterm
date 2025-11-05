# QuicDomainServer

The `QuicDomainServer` struct specifies configuration for listening
on a [QUIC Domain](../../multiplexing.md#quic-domains).

It is a lua object with the following fields:

```lua
config.quic_servers = {
  {
    -- The host:port combination on which the server will listen
    -- for QUIC connections
    bind_address = 'server.hostname:9001',

    -- Certificate lifetime in days (default: 7).
    -- Shorter lifetimes provide better security by limiting exposure
    -- if a certificate is compromised.
    certificate_lifetime_days = 7,

    -- the path to an x509 PEM encoded private key file.
    -- If unspecified, wezterm will generate a self-signed key.
    -- pem_private_key = "/some/path/key.pem",

    -- the path to an x509 PEM encoded certificate file
    -- If unspecified, wezterm will generate a self-signed certificate.
    -- pem_cert = "/some/path/cert.pem",

    -- the path to an x509 PEM encoded CA chain file.
    -- If unspecified, wezterm will generate a CA certificate.
    -- pem_ca = "/some/path/ca.pem",

    -- A set of paths to load additional CA certificates.
    -- Each entry can be either the path to a directory or to a PEM encoded
    -- CA file.  If an entry is a directory, then its contents will be
    -- loaded as CA certs and added to the trust store.
    -- pem_root_certs = { "/some/path/ca1.pem", "/some/path/ca2.pem" },

    -- Maximum idle timeout for QUIC connections (default: 30 seconds)
    -- max_idle_timeout = 30,

    -- Keep-alive interval for QUIC connections (optional)
    -- If set, sends periodic keep-alive frames to detect dead connections
    -- keep_alive_interval = 5,
  },
}
```

## Automatic Certificate Generation

If you don't specify certificate files, wezterm will automatically generate
certificates for you:

- A self-signed CA certificate (stored in wezterm's PKI directory)
- Self-signed server certificates with the specified lifetime
- Client certificates are generated on-demand when clients request them

This is the recommended approach for most users, as it provides security
without the complexity of managing certificates manually.

## Certificate Management

The server manages certificate lifecycle:

- **Generation**: Certificates are generated with the specified `certificate_lifetime_days`
- **Distribution**: When a client connects via SSH bootstrap, the server provides
  the CA and a client certificate
- **Renewal**: The server generates new certificates on-demand, allowing clients
  to refresh their certificates without re-bootstrapping
- **Default Location**: Generated certificates are stored in
  `~/.local/share/wezterm/pki/` (for user mode) or
  `/etc/wezterm/pki/` (for system mode)

## Binding

The `bind_address` should specify both the interface and port to listen on:

- `localhost:9001` - Listen only on localhost (secure, but local only)
- `127.0.0.1:9001` - Listen on IPv4 loopback only
- `[::1]:9001` - Listen on IPv6 loopback only
- `[::]:9001` - Listen on all IPv6 interfaces (and IPv4 via IPv6 dual-stack)
- `0.0.0.0:9001` - Listen on all IPv4 interfaces

## Firewall Configuration

Make sure your firewall allows UDP traffic on the configured port:

```bash
# Linux example with ufw
sudo ufw allow 9001/udp

# macOS example with pfctl
# Add to /etc/pf.conf:
# pass in proto udp from any to any port 9001
```

## Performance

QUIC servers can handle thousands of concurrent connections and benefit from:

- Connectionless UDP transport (lower overhead than TCP)
- Multiplexed streams (handle multiple requests efficiently)
- Automatic congestion control
- Connection migration support

## Network Resilience

The QUIC server automatically supports:

- Client connection migration (network changes)
- NAT traversal via UDP
- Stateless reset handling
- Path validation

## See Also

- [Multiplexing Documentation](../../multiplexing.md#quic-domains)
- [QUIC Protocol](https://en.wikipedia.org/wiki/QUIC)
- [QuicDomainClient](QuicDomainClient.md)
