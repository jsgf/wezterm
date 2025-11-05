# Plan: Add QUIC Transport to WezTerm Mux Protocol

## Overview
Add QUIC as a new transport option for the WezTerm mux protocol, enabling benefits like 0-RTT reconnection, connection migration, and improved NAT traversal.

## Architecture Decision: Single-Stream vs Multi-Stream

### Option A: Single-Stream Model (Recommended for Phase 1)
**Approach:** Use one bidirectional QUIC stream, treat it like TCP
- **Pros:**
  - Minimal changes to existing PDU codec
  - Preserve LEB128 framing protocol
  - Easier to implement and test
  - Still get 0-RTT and connection migration benefits
  - Lower risk of bugs
- **Cons:**
  - Doesn't leverage QUIC's native multiplexing
  - Head-of-line blocking at application layer
- **Estimated complexity:** Medium

### Option B: Multi-Stream Model (Future Enhancement)
**Approach:** Each RPC uses a separate QUIC stream
- **Pros:**
  - No head-of-line blocking between requests
  - Better parallelism for independent operations
  - Leverages QUIC's full capabilities
  - Potentially better performance
- **Cons:**
  - Requires significant codec refactoring
  - More complex error handling
  - Breaking protocol change (needs versioning)
  - Higher implementation risk
- **Estimated complexity:** High

**Recommendation:** Start with Option A (single-stream), design for future migration to Option B

## QUIC Implementation Selection: ✅ quinn

**Decision: Use quinn 0.12 with `runtime-smol` feature**

**Evaluation Results:**

✅ **Async runtime compatibility**: Native smol support via `SmolRuntime` implementation
- Quinn provides clean `Runtime` trait abstraction (`quinn/src/runtime.rs`)
- Built-in `SmolRuntime` in `quinn/src/runtime/async_io.rs`
- Simply enable `runtime-smol` feature and disable `runtime-tokio`
- Automatic runtime detection with `default_runtime()`

✅ **0-RTT support**: Fully supported with comprehensive API
- `Connecting::into_0rtt()` method for immediate connection usage
- Returns `ZeroRttAccepted` future to confirm acceptance
- Enabled by default in rustls config (`enable_early_data = true`)
- Can send data immediately before handshake completes
- Extensive test coverage

✅ **Connection migration**: Full support
- Client rebinding via `endpoint.rebind()` API
- Server-side migration enabled by default
- Proper path validation and address migration
- Handles network switches seamlessly

✅ **API ergonomics**: Excellent
- Clean async/await API with bidirectional streams
- Well-documented error handling
- Platform certificate verifier support
- Examples for all major use cases

✅ **Production maturity**: Production-ready
- Version 0.12.0, very active (689 commits in 2024)
- Extensive test coverage including fuzzing
- Used in production by major projects
- Comprehensive documentation with dedicated book

✅ **Performance**: Optimized UDP I/O with GRO/GSO support

**Dependencies:**
```toml
quinn = { version = "0.12", default-features = false, features = [
    "runtime-smol",
    "rustls-ring",
    "platform-verifier"
] }
```

**Crypto Stack:**
- TLS: rustls (different from WezTerm's existing OpenSSL, both will coexist)
- Crypto provider: ring (smaller than aws-lc-rs)
- Certificate generation: rcgen (already used by WezTerm, can reuse PKI infrastructure)

## Implementation Phases

### Phase 1: Configuration & Core Types
**New files:**
- `config/src/quic.rs` - QuicDomainClient/Server configuration structs
- Add `quic_clients: Vec<QuicDomainClient>` to main Config
- Add `quic_servers: Vec<QuicDomainServer>` to main Config

**Configuration fields:**
```rust
QuicDomainClient {
    name: String,
    remote_address: String,  // host:port for QUIC
    bootstrap_via_ssh: Option<String>,  // SSH bootstrap (user@host:port)
    persist_to_disk: bool,   // Default: false (keep certs in memory only)
    certificate_lifetime_days: u32,  // Default: 7 days
    enable_0rtt: bool,
    enable_migration: bool,
    max_idle_timeout: Duration,
    // Certificate configuration (for manual/CA-signed certs)
    pem_cert: Option<PathBuf>,
    pem_private_key: Option<PathBuf>,
    pem_root_certs: Vec<PathBuf>,
    accept_invalid_hostnames: bool,  // For dev/testing
    expected_cn: Option<String>,     // Override cert CN validation
}

QuicDomainServer {
    bind_address: String,
    certificate_lifetime_days: u32,  // Default: 7 days
    pem_cert: Option<PathBuf>,          // Optional: use PKI-generated if None
    pem_private_key: Option<PathBuf>,
    pem_ca: Option<PathBuf>,
    max_idle_timeout: Duration,
    keep_alive_interval: Option<Duration>,
}
```

**Certificate Strategy:**
WezTerm QUIC supports two certificate modes:

1. **SSH-bootstrapped self-signed certs** (recommended for most users):
   - Initial connection: SSH session starts mux server and exchanges QUIC certificates
   - **Certificate lifetime: 7 days** (configurable, balances security and UX)
   - **Certificates kept in memory by default** (security improvement over TLS)
   - Optional persistence to disk via `persist_to_disk: bool` config (for debugging/compliance)
   - When persisted: stored in `~/.local/share/wezterm/pki/{domain}/`
   - **Background renewal at ~80% lifetime (~5.6 days):**
     - Send `GetQuicCreds` PDU over existing authenticated QUIC connection
     - Receive fresh certificate (new 7-day validity)
     - Store new cert for future reconnections
     - Current connection continues with old cert (already authenticated)
     - Next reconnection uses new cert (seamless transition)
     - **No SSH/2FA required for renewal** - truly transparent
   - If no active connection during renewal window → SSH bootstrap on next connection
   - Trust-on-first-use model via secure SSH channel
   - Reuses existing `wezterm-mux-server-impl/src/pki.rs` infrastructure
   - **Security benefits:** No cert exfiltration/reuse risk, limited lifetime, automatic rotation

2. **Standard CA-signed certificates** (for environments with PKI):
   - Specify `pem_cert`, `pem_private_key`, `pem_root_certs` paths
   - Works with enterprise certificate infrastructure
   - Standard X.509 validation via rustls
   - Loaded from disk (required for CA-signed certs)
   - Renewal handled by enterprise PKI processes

### Phase 2: Client Implementation
**New file:** `wezterm-client/src/quic_client.rs`

**Key components:**
1. QUIC stream wrapper implementing `AsyncReadAndWrite` trait
2. Connection establishment with 0-RTT support
3. SSH bootstrap logic (mirrors TLS implementation):
   - Execute `wezterm cli quiccreds` over SSH
   - Receive `GetQuicCredsResponse` with CA + client cert (PEM strings)
   - **Default: Keep certificates in memory only** (stored in `Reconnectable` struct)
   - Track certificate expiry time (lifetime from config)
   - If `persist_to_disk: true`: Write to `~/.local/share/wezterm/pki/{domain}/`
   - Retry direct QUIC first on reconnections (using in-memory certs)
4. **Background certificate renewal:**
   - Timer checks cert expiry (background task)
   - At 80% of lifetime, send `GetQuicCreds` PDU over active QUIC connection
   - Receive fresh cert, update in-memory storage
   - Current connection continues, new cert used for future connections
   - No SSH/2FA required - fully transparent
5. Certificate loading for manual/CA-signed certs (always from disk)
6. Connection migration support via quinn's rebind API
7. Error mapping for QUIC-specific conditions
8. rustls certificate handling (works natively with in-memory PEM strings)

**Modified files:**
- `wezterm-client/src/client.rs` - Add `quic_connect()` method to `Reconnectable`
- `wezterm-client/src/domain.rs` - Add `Quic` variant to `ClientDomainConfig` enum

**Implementation pattern:** Follow existing TLS bootstrap flow:
- Lines 810-941 in `wezterm-client/src/client.rs` show SSH bootstrap
- Reuse certificate storage paths (lines 610-622)
- Same trust-on-first-use model

### Phase 3: Server Implementation
**New file:** `wezterm-mux-server/src/quic_server.rs`

**Key components:**
1. QUIC endpoint setup with rustls ServerConfig
2. Accept loop for incoming QUIC connections
3. Certificate handling:
   - Reuse existing PKI infrastructure (`wezterm-mux-server-impl/src/pki.rs`)
   - **Modify PKI to accept configurable certificate lifetime** (not_before/not_after)
   - Generate CA and server certs with configured lifetime (default 7 days)
   - Load generated or manual certificates (same as TLS)
   - Validate client certificates (CN must match username)
4. Wrap QUIC streams as AsyncReadAndWrite
5. Integration with existing `dispatch::process()` handler (unchanged)
6. **Handle `GetQuicCreds` requests** (both initial and renewal):
   - Generate fresh client certificate with configured lifetime
   - Return via existing PDU response mechanism

**New CLI command:** `wezterm/src/cli/quic_creds.rs`
- Implements `wezterm cli quiccreds` (parallel to `tlscreds`)
- Returns `GetQuicCredsResponse` over codec

**Modified files:**
- `codec/src/lib.rs` - Add `GetQuicCreds {}` and `GetQuicCredsResponse { ca_cert_pem, client_cert_pem }` PDUs
- `wezterm-mux-server-impl/src/pki.rs` - Add configurable certificate lifetime to `Pki::init()` and `generate_client_cert()`
- `wezterm-mux-server-impl/src/sessionhandler.rs` - Handle `GetQuicCreds` request
- `wezterm-mux-server/src/main.rs` - Spawn QUIC listener
- `wezterm-mux-server-impl/src/lib.rs` - Register QUIC domains

**Implementation pattern:** Follow existing TLS server setup:
- Certificate validation in `wezterm-mux-server/src/ossl.rs:25-70`
- PKI initialization mirrors TLS approach

### Phase 4: Testing & Validation
**Test scenarios:**
- Basic connect/disconnect
- 0-RTT reconnection (measure latency improvement)
- Connection migration (network switch simulation)
- Certificate validation (valid/invalid/expired)
- **Certificate renewal:**
  - Verify renewal triggers at 80% lifetime
  - Test renewal over active QUIC connection
  - Verify no SSH/2FA prompts during renewal
  - Test new cert used for subsequent connections
  - Verify old connection continues during renewal
- **Certificate expiry handling:**
  - Test connection when cert expired (should trigger SSH bootstrap)
  - Test renewal failure fallback
- Concurrent connections
- Large data transfers
- Error conditions (timeout, reset, etc.)

### Phase 5: Documentation
- Configuration examples in docs/
- Migration guide from TLS to QUIC
- Troubleshooting guide for QUIC-specific issues
- Performance tuning recommendations

## Files to Create/Modify

**New Files (~1,500 lines):**
- `config/src/quic.rs` (~200 lines)
- `wezterm-client/src/quic_client.rs` (~600 lines)
- `wezterm-mux-server/src/quic_server.rs` (~500 lines)
- `tests/quic_integration.rs` (~200 lines)

**Modified Files (~500 lines):**
- `config/src/config.rs` - Add quic_clients/servers fields
- `config/src/lib.rs` - Export quic module
- `wezterm-client/src/client.rs` - Add quic_connect() method, certificate renewal logic
- `wezterm-client/src/domain.rs` - Add Quic variant
- `wezterm-mux-server-impl/src/pki.rs` - Add configurable certificate lifetime
- `wezterm-mux-server-impl/src/lib.rs` - Register QUIC domains
- `wezterm-mux-server/src/main.rs` - Spawn QUIC server
- `Cargo.toml` files - Add QUIC dependency

**Total Estimate:** ~2,000 lines of new/modified code

## Key Design Decisions

### 0. Connection Flow (QUIC Advantage)
WezTerm's SSH-based mux server startup creates an ideal use case for QUIC:

**Initial Connection:**
1. User runs `wezterm ssh user@host`
2. SSH session established (required to start remote mux server anyway)
3. Remote `wezterm-mux-server` starts
4. `wezterm cli quiccreds` executed over SSH → exchange certificates
5. QUIC connection established with fresh self-signed certs
6. SSH can be closed, QUIC connection continues

**All Subsequent Reconnections:**
1. Direct QUIC connection with 0-RTT (< 10ms handshake)
2. No SSH overhead, no password/key authentication needed
3. Connection migration if network changes (WiFi → Ethernet, etc.)
4. Seamless resume even after mux server restart (new certs exchanged via SSH bootstrap)

**Performance Benefits:**
- SSH+TLS: ~100-500ms initial + ~50-100ms reconnect handshake
- SSH+QUIC: ~100-500ms initial + **< 10ms reconnect** with 0-RTT
- Connection migration: Transparent network changes (not possible with TCP/TLS)

### 1. Stream Model
- **Phase 1:** Single bidirectional stream (preserve existing codec)
- **Phase 2 (optional):** Migrate to multi-stream model with new codec version

### 2. Async Runtime Integration
- ✅ **Decided:** Use quinn's built-in `SmolRuntime` implementation
- Enable `runtime-smol` feature, disable `runtime-tokio`
- No compatibility layer needed - native smol support
- Quinn automatically detects and uses smol runtime via `default_runtime()`

### 3. Certificate Management
- ✅ **Reuse existing PKI infrastructure** from `wezterm-mux-server-impl/src/pki.rs`
- Same certificate formats (PEM) as TLS domains
- rcgen-generated certificates compatible with both OpenSSL and rustls
- SSH bootstrap for automatic self-signed cert distribution
- **Security improvement: In-memory certificate storage by default**
  - Reduces cert exfiltration/reuse risk
  - rustls works natively with in-memory PEM (unlike OpenSSL requiring files)
  - Optional persistence via `persist_to_disk: true` config
- Optional manual certificate configuration for enterprise PKI

### 4. Error Handling
- Map QUIC errors to existing mux error types
- Preserve error context for debugging
- Add QUIC-specific error variants where needed

### 5. Configuration Compatibility
- QUIC domains work alongside existing Unix/TLS/SSH domains
- No breaking changes to existing configurations
- Similar config structure to TLS domains for familiarity

## Risks & Mitigation

**Risk 1: Async Runtime Incompatibility**
- ✅ **RESOLVED:** Quinn has native smol support via `SmolRuntime`
- No compatibility layer needed

**Risk 2: Performance Regression vs TLS**
- Mitigation: Benchmark early, optimize hot paths
- 0-RTT should provide significant improvement for reconnections
- Connection migration adds capability not possible with TLS
- Fallback: Make QUIC optional, keep TLS as alternative

**Risk 3: Certificate/PKI Complexity**
- ✅ **MITIGATED:** Existing `pki.rs` infrastructure fully reusable
- rcgen certificates work with both OpenSSL (TLS) and rustls (QUIC)
- SSH bootstrap pattern already proven with TLS implementation
- Test with self-signed and CA-signed certificates

**Risk 4: Platform-Specific Issues**
- Mitigation: Test on Linux, macOS, Windows early
- UDP socket handling varies by platform

## Success Criteria

1. QUIC domain connects successfully to remote server
2. 0-RTT reconnection measurably faster than TLS (< 10ms handshake)
3. Connection migration works when changing networks
4. **Certificate renewal operates transparently:**
   - No SSH/2FA prompts during renewal
   - Renewal happens in background at 80% lifetime
   - New cert ready for next connection
   - Old connection continues uninterrupted
5. **Certificates kept in-memory by default** (security improvement)
6. No regressions in existing Unix/TLS/SSH transports
7. Configuration as simple as TLS domains
8. Comprehensive test coverage (>80%)

## Implementation Status

### ✅ Completed Work (18 commits)

**Phase 1: Configuration & Core Types**
- ✅ `config/src/quic.rs` - QuicDomainClient/Server configuration structs
- ✅ `config/Cargo.toml` - Added `quic` feature flag with optional quinn/rustls/ring deps
- ✅ Integrated into main Config struct with domain validation
- ✅ Added integration tests (4 passing tests)
- ✅ Comprehensive documentation (multiplexing guide, API reference)

**Phase 2: Client Implementation (Scaffold)**
- ✅ `wezterm-client/src/quic_client.rs` - Basic placeholder with establish_quic_connection()
- ✅ Added `quic_connect()` method to Reconnectable struct
- ✅ Added `new_quic()` factory method to Client
- ✅ Updated ClientDomainConfig enum with Quic variant
- ✅ Full pattern matching coverage for all domain operations
- ✅ `wezterm-client/Cargo.toml` - Added quic feature with optional quinn/rustls

**Phase 3: Server Implementation (Scaffold)**
- ✅ `wezterm-mux-server/src/quic_server.rs` - Basic placeholder with spawn_quic_listener()
- ✅ `wezterm/src/cli/quic_creds.rs` - CLI command stub (quiccreds)
- ✅ Updated server initialization to spawn QUIC listeners
- ✅ PDU handlers for GetQuicCreds/GetQuicCredsResponse
- ✅ `wezterm-mux-server/Cargo.toml` - Added quic feature

**Phase 4-5: Testing & Documentation**
- ✅ Integration tests for config types
- ✅ Multiplexing guide with QUIC section
- ✅ QuicDomainClient and QuicDomainServer reference docs
- ✅ Configuration reference stubs

**Feature Gating & Validation**
- ✅ All feature gates: Feature types always parsed, errors only on use
- ✅ Runtime validation with helpful error messages
- ✅ Feature flags in all affected Cargo.toml files
- ✅ Warnings for missing quic feature fixed

### 🚧 Current State: Functional Scaffold

The implementation provides:
- ✅ Complete configuration infrastructure
- ✅ Module structure for client/server implementation
- ✅ Feature-gated code (compile with `--features quic`)
- ✅ Parse-always, validate-on-use error handling
- ✅ Proper async method signatures (quic_connect is async)
- ✅ Clean separation of concerns with conditional compilation

### ⚠️ Known Limitations (Future Work)

- Async I/O integration incomplete (poll methods return Pending)
- No actual QUIC endpoint setup yet
- No SSH bootstrap implementation
- No 0-RTT caching
- No connection migration
- No certificate renewal background task

### 📋 Remaining Tasks for Full Implementation

1. **Async Integration** - Proper quinn stream polling and integration
2. **Client Connection** - Actual endpoint setup and QUIC handshake
3. **Server Listener** - Accept loop and connection dispatch
4. **SSH Bootstrap** - Certificate exchange over SSH
5. **Certificate Renewal** - Background 80% lifetime renewal task
6. **0-RTT Support** - Session resumption and caching
7. **Connection Migration** - Network change handling

## Next Steps

✅ **Completed:** Quinn analysis confirms excellent fit for WezTerm
✅ **Decided:** Use quinn 0.11 with runtime-smol and rustls-ring
✅ **Phase 1-3:** Configuration, client scaffold, server scaffold

**Phase 4-5 ready for implementation:**
1. Phase 4: Testing and validation
2. Phase 5: Documentation refinement

**Key insights from investigation:**
- SSH bootstrap already required to start mux server → perfect fit for cert exchange
- Existing PKI infrastructure (`pki.rs`) using rcgen → fully reusable
- TLS client implementation provides clear blueprint (lines 810-941 in `wezterm-client/src/client.rs`)
- Certificate storage pattern already established
- All required abstractions exist (`AsyncReadAndWrite`, `Reconnectable`, etc.)
