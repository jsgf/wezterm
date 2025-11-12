ABSOLUTELY ESSENTIAL FUNCTIONALITY

Project cannot be considered complete without these features:
- QUIC transport protocol support for networking
- Standard TLS with certs
- SSH bootstrap with ephemeral certs
  - Auto-start wezterm-mux on first SSH connection
  - Establish ephemeral certs
  - Transparent renewal over QUIC during cert lifetime
  - SSH renewal for new client or if cert expires while offline
- Appropriate config for all of the above
- Demonstrate all functionality working (ad-hoc testing OK for now)

Notes:
- quinn checked out to crates.io published version 0.11.2 at /home/jeremy/git/quinn
- Overall plan in @QUIC_PLAN.md
- adhoc test plan in @QUIC_TESTING_PLAN.md
- ABSOLUTELY NO FILE MODIFICATION outside this directory. **ALL** test state should be under ./tmp. Do not use /tmp, /run, ~, or any other external dirs
- Use the TLS implementation as a guide and only deviate from that design if there's a fundamental reason to.
- **Client and Server are completely separate processes** - ESSENTIAL not to confuse them in analysis. Each has its own executor, Quinn endpoint, certificates, etc.
- Use `cargo check` to validate code changes