return {
  -- QUIC Client Configuration - client only
  quic_clients = {
    {
      name = "quic_test",
      remote_address = "localhost:8080",
      bootstrap_via_ssh = "localhost",
      remote_wezterm_path = "/home/jeremy/git/wezterm/target/release/wezterm",
      persist_to_disk = true,
      certificate_lifetime_days = 7,
      enable_0rtt = true,
      enable_migration = true,
      max_idle_timeout = 30,  -- seconds
    },
  },
}
