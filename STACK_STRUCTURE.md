The current commit stack is a meandering history of development, but we
need turn it into something that can be actually reviewed.

This means:
- drop everything in tmp/ used for testing
- keep the claude files *COMPLETELY* separate from all other commits
- clean up prints used for debugging
- put generic fixes into early commits before anything quic-related is introduced
  - refactor to use select!
  - refactor ssh bootstrap
  - other bugfixes. TODO: research stack and find other instances
- define quic feature
- put in place new config schemas for quic
- implement server
- implement client

Analyze the *entire* branch from main..quic_mux and categorize each change as above.
Create a new branch "quic-mux-refactor" and generate a structured series
of commits with appropriate commit comments.
Every commit should compile cleanly with and without the quic feature (once introduced).
The result *must* be functionally equivalent to the current branch.

---

# Detailed Refactoring Plan (28 Commits)

## Phase 1: Generic Fixes & Refactors (Commits 1-5)
Pre-QUIC improvements that benefit all transports.

### Commit 1: Fix lifetime elision warnings
- Files: `lfucache/src/lib.rs`, `mux/src/tab.rs`
- Source commit: 3c87e5179
- Add explicit `'_` lifetime annotations to `EntryData` and `MappedMutexGuard` return types

### Commit 2: Add chrono 'now' feature
- Files: `Cargo.toml`
- Source commit: ac0172d95
- Required for PKI timestamp generation

### Commit 3: Refactor dispatch.rs to use futures::select!
- Files: `wezterm-mux-server-impl/src/dispatch.rs`
- Source commit: 2e3cb0de8
- Replace `smol::future::or()` with `futures::select!` macro for fair concurrent event handling
- Clean up excessive debug logs before committing

### Commit 4: Refactor client event loop to use futures::select!
- Files: `wezterm-client/src/client.rs` (client_thread_async function)
- Source commit: Part of 04521aee4 (extract from WIP)
- Replace nested three-way `smol::future::or()` race with `futures::select!` macro
- Handles RPC requests, incoming PDUs, and renewal timer concurrently
- Benefits all connection types: Unix, TLS, SSH, and QUIC

### Commit 5: Fix mux notification delivery
- Files: `mux/src/lib.rs`
- Source commit: Part of 6890184ca (exclude QUIC server changes)
- Generic bug fix ensuring pane output notifications reach all subscribers

## Phase 2: SSH Bootstrap Refactor (Commit 6)
Extract reusable SSH credential exchange logic.

### Commit 6: Extract SSH bootstrap module
- Files: `wezterm-client/src/ssh_bootstrap.rs`, `wezterm-client/src/lib.rs`, `wezterm-client/src/client.rs`
- Source commit: Part of 3a97f7cb0 (exclude tmp/ changes)
- Functions: `establish_ssh_session()`, `execute_remote_command_for_pdu()`
- Update TLS `tls_connect()` to use new helpers
- Reusable for both TLS and QUIC bootstrap flows

## Phase 3: QUIC Feature Definition (Commits 7-9)
Add dependency infrastructure for QUIC support.

### Commit 7: Add QUIC workspace dependencies
- Files: `Cargo.toml`
- Source commit: 84d39e37f + versions from e7b135301
- Add quinn, rustls, ring with correct versions

### Commit 8: Add quic feature to config crate
- Files: `config/Cargo.toml`
- Source commit: 29a2b38a9
- Feature gate for QUIC config types

### Commit 9: Add quic features to affected crates
- Files: `wezterm-client/Cargo.toml`, `wezterm-mux-server/Cargo.toml`, `wezterm-mux-server-impl/Cargo.toml`, `wezterm/Cargo.toml`, `codec/Cargo.toml`
- Source commit: Parts of 0e15d5341, 79d5ad200, 3018e3064
- Complete feature gating infrastructure

## Phase 4: QUIC Config Schema (Commits 10-13)
Define user-facing QUIC configuration.

### Commit 10: Create QUIC configuration types
- Files: `config/src/quic.rs`, `config/src/lib.rs`
- Source commit: c718c4f67
- Types: `QuicDomainClient`, `QuicDomainServer` with validation

### Commit 11: Integrate into main Config
- Files: `config/src/config.rs`
- Source commit: 42cd3c7be
- Add `quic_clients` and `quic_servers` fields

### Commit 12: Add integration tests
- Files: `config/tests/quic_integration.rs`
- Source commit: 91cac36e0

### Commit 13: Add documentation
- Files: `docs/multiplexing.md`, `docs/config/lua/QuicDomainClient.md`, etc.
- Source commit: a54e74480, e22d5256f

## Phase 5: QUIC Protocol Layer (Commit 14)
Define credential exchange protocol.

### Commit 14: Add credential exchange PDUs
- Files: `codec/src/lib.rs`
- Source commit: 194e47b50
- PDUs: `GetQuicCreds`, `GetQuicCredsResponse`

## Phase 6: QUIC Client Implementation (Commits 15-20)
Full client-side QUIC support.

### Commit 15: Client domain scaffold
- Files: `wezterm-client/src/domain.rs`, `wezterm-client/src/lib.rs`, `wezterm-client/src/quic_client.rs`
- Source commit: 0aac69df7
- Add `ClientDomainConfig::Quic` variant

### Commit 16: Client connection methods
- Files: `wezterm-client/src/client.rs`
- Source commit: c2d396b89, a033e9074, dd585c1e5
- Methods: `quic_connect()`, `new_quic()`, `try_quic_connect()`

### Commit 17: Basic connection establishment
- Files: `wezterm-client/src/quic_client.rs`
- Source commit: 79d5ad200
- Function: `establish_quic_connection()` with Quinn endpoint

### Commit 18: QuicStream with AsyncRead/AsyncWrite
- Files: `wezterm-client/src/quic_client.rs`
- Source commit: d03be4746, 8f890a15f, 7d3ff7d71
- Bridge quinn's streams to AsyncReadAndWrite trait

### Commit 19: SSH bootstrap for QUIC
- Files: `wezterm-client/src/client.rs`, `wezterm-client/src/quic_client.rs`
- Source commit: Parts of 3018e3064, 3a97f7cb0
- Execute `wezterm cli quiccreds` over SSH

### Commit 20: Certificate management
- Files: `wezterm-client/src/client.rs`
- Source commit: 4e15e7096, c05c5adec, 032cbceb3
- In-memory cert storage, expiry checking, background renewal

## Phase 7: QUIC Server Implementation (Commits 21-25)
Full server-side QUIC support.

### Commit 21: Server scaffold and CLI
- Files: `wezterm-mux-server/src/quic_server.rs`, `wezterm/src/cli/quic_creds.rs`, `wezterm/src/cli/mod.rs`, `wezterm-mux-server/src/main.rs`
- Source commit: 4327f8b8c, 0e15d5341
- `spawn_quic_listener()`, quiccreds CLI command

### Commit 22: Credential handling
- Files: `wezterm-mux-server-impl/src/sessionhandler.rs`
- Source commit: Part of 4327f8b8c
- Handle `GetQuicCreds` PDU requests

### Commit 23: Configurable certificate lifetime
- Files: `wezterm-mux-server-impl/src/pki.rs`
- Source commit: 3b59f8a7d

### Commit 24: Server endpoint implementation
- Files: `wezterm-mux-server/src/quic_server.rs`
- Source commit: d5a5fc581, 25ef2017d, 4180a57ca
- Quinn endpoint, rustls config, connection accept loop

### Commit 25: Server event loop integration
- Files: `wezterm-mux-server/src/quic_server.rs`
- Source commit: 9270c0503, part of 6890184ca
- QuicStream wrapper, process_quic_stream with futures::select!
- Mux notification subscription (matches dispatch.rs pattern)

## Phase 8: Domain Registration (Commit 26)

### Commit 26: Register QUIC domains
- Files: `wezterm-mux-server-impl/src/lib.rs`
- Source commit: f54ad2688

## Phase 9: Final Cleanup (Commit 27)

### Commit 27: Formatting
- Files: Multiple
- Source commit: 2592517f0

## Phase 10: Claude Documentation (Commit 28)

### Commit 28: Claude project documentation
- Files: `CLAUDE.md`, `QUIC_PLAN.md`, `QUIC_TESTING_PLAN.md`, `.claude/settings.local.json`
- Isolated final commit, separate from all code changes

---

## Key Decisions

### What Gets Dropped
1. **All tmp/ directory files** - Testing infrastructure not kept in history
2. **.cargo/config.toml changes** - Temporary rustflags
3. **WIP commits** - Content preserved in clean commits
4. **Excessive debug logs** - Reduce to essential logging only
5. **Intermediate Claude doc updates** - Keep final state only

### Why This Order
- **Commits 1-6**: Generic improvements benefiting all transports, not QUIC-specific
- **Commits 7-9**: Feature infrastructure foundation
- **Commits 10-14**: Configuration and protocol layer
- **Commits 15-20**: Client implementation (depends on 7-14)
- **Commits 21-26**: Server implementation (depends on 7-14)
- **Commits 27-28**: Final touches and documentation

### Verification
Every commit must:
1. Compile cleanly without quic feature: `cargo check`
2. Compile cleanly with quic feature: `cargo check --features quic`
3. Not introduce regressions to existing functionality
4. Have a clear, descriptive commit message

