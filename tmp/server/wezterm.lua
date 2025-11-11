return {
  -- QUIC Server Configuration - server only
  quic_servers = {
    {
      bind_address = "[::]:8080",  -- Dual-stack: listen on both IPv4 and IPv6
      certificate_lifetime_days = 7,
      max_idle_timeout = 30,  -- seconds
    },
  },
}
