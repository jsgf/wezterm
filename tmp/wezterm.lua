return {
  -- QUIC Server Configuration
  quic_servers = {
    {
      bind_address = "127.0.0.1:8080",
      certificate_lifetime_days = 7,
      max_idle_timeout = 30,  -- seconds
    },
  },

  -- QUIC Client Configuration
  quic_clients = {
    {
      name = "quic_test",
      remote_address = "127.0.0.1:8080",
      bootstrap_via_ssh = "localhost",
      remote_wezterm_path = "/home/jeremy/git/wezterm/target/release/wezterm",
      persist_to_disk = true,
      certificate_lifetime_days = 7,
      enable_0rtt = true,
      enable_migration = true,
      max_idle_timeout = 30,  -- seconds
      accept_invalid_hostnames = true,  -- Workaround for localhost cert
    },
  },
}
