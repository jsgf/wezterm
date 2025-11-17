# Multi-Stream QUIC for WezTerm Mux: Design Document

## Executive Summary

Extend wezterm's QUIC mux transport to use multiple streams per connection, isolating per-pane traffic to avoid head-of-line blocking. TLS transport remains unchanged, modeling as single stream (N=1).

**Status:** Feasibility analysis complete - RECOMMENDED for implementation

---

## Motivation

**Problem:** Single QUIC stream behaves like TCP - one high-output pane blocks other interactive panes.

**Solution:** Use QUIC's native multi-stream capability to isolate panes.

**Benefits:**
- High-output pane doesn't block interactive panes
- QUIC scheduler optimizes across streams independently
- Better network utilization under mixed workloads

---

## Protocol Changes

### New PDU: `BindPaneToStream`

```rust
#[derive(Deserialize, Serialize, PartialEq, Debug)]
pub struct BindPaneToStream {
    pub pane_id: PaneId,
}
```

**Semantics:**
- Sent on stream N to bind `pane_id` to stream N
- Received by server/client: updates routing table
- Can rebind existing panes (e.g., rebind to stream 0 to "unbind")
- No response PDU needed

**Add to codec/src/lib.rs:**
```rust
pub enum Pdu {
    // ... existing PDUs ...
    BindPaneToStream(BindPaneToStream),  // New
}
```

### Stream Semantics

**Stream 0 (primary):**
- First bidirectional stream opened by client
- Used for session-level PDUs: `ListPanes`, `GetCodecVersion`, `Ping`, etc.
- Default stream for unbound panes
- Always available

**Stream N (pane-specific):**
- Created by client via `connection.open_bi()`
- Bound to specific pane via `BindPaneToStream`
- Carries all traffic for that pane
- Falls back to stream 0 if stream closes

### Routing Rules

**Client → Server:**
- Look up `pane_streams[pane_id]`, default to stream 0 if not found
- Send PDU on that stream
- PDUs without `pane_id` always use stream 0

**Server → Client:**
- Look up `pane_streams[pane_id]`, default to stream 0 if not found
- Send PDU on that stream
- Unilateral PDUs (serial=0) use pane's bound stream

**Key principle:** Any PDU can arrive on any stream (no synchronization required)

---

## Protocol Flows

### 1. New Pane Creation

```
Client: open_bi() → stream 1, StreamId = 1
Client → Server (stream 1): SpawnV2 { domain: X, ... }
Client → Server (stream 1): BindPaneToStream { pane_id: 42 }
Client: pane_streams[42] = StreamId(1)

Server: Receives on stream 1
Server → Client (stream 1): SpawnResponse { pane_id: 42, ... }
Server: pane_streams[42] = StreamId(1)

Future: All PDUs for pane 42 use stream 1
```

### 2. Split Pane

```
// Original pane 42 on stream 1
Client: open_bi() → stream 2, StreamId = 2
Client → Server (stream 2): SplitPane { pane_id: 42, ... }
Client → Server (stream 2): BindPaneToStream { pane_id: 99 }
Client: pane_streams[99] = StreamId(2)

Server → Client (stream 2): SpawnResponse { pane_id: 99, ... }
Server: pane_streams[99] = StreamId(2)

Result:
- Original pane 42 remains on stream 1
- New split pane 99 uses stream 2
```

### 3. Reconnection

```
Client connects, opens stream 0
Client → Server (stream 0): ListPanes
Server → Client (stream 0): ListPanesResponse { panes: [17, 42, 99] }

// All panes default to stream 0 after reconnect
// Client selectively isolates important panes:
Client: open_bi() → stream 1
Client → Server (stream 1): BindPaneToStream { pane_id: 42 }
Client: pane_streams[42] = StreamId(1)

Client: open_bi() → stream 2
Client → Server (stream 2): BindPaneToStream { pane_id: 99 }
Client: pane_streams[99] = StreamId(2)

// Pane 17 remains on stream 0, panes 42 and 99 isolated
```

### 4. Stream Closure

```
// Stream 1 closes unexpectedly
Server: Detects stream 1 read error
Server: For all panes where pane_streams[pane_id] == StreamId(1):
  pane_streams.remove(pane_id)  // Falls back to stream 0
Server: Continue processing on stream 0

// Client does same cleanup
```

### 5. Connection Closure

```
Connection closes
Quinn: All streams fail with ConnectionError::LocallyClosed
All stream tasks: decode_async returns error → loop exits → task terminates
Both client and server: pane_streams.clear()
```

---

## Implementation Architecture

### QUIC Client Changes

**Location:** `wezterm-client/src/quic_client.rs`

**New structures:**
```rust
struct QuicConnectionState {
    connection: quinn::Connection,
    streams: Arc<Mutex<HashMap<StreamId, StreamHandle>>>,
    pane_streams: Arc<Mutex<HashMap<PaneId, StreamId>>>,
}

struct StreamHandle {
    send: quinn::SendStream,
    tx: Sender<OutgoingPdu>,  // Channel to stream task
}

struct OutgoingPdu {
    pdu: Pdu,
    serial: u64,
}
```

**Stream management:**
```rust
// Open new stream for pane
async fn open_pane_stream(&self, pane_id: PaneId) -> Result<StreamId> {
    let (send, recv) = self.connection.open_bi().await?;
    let stream_id = send.id();

    // Spawn task to handle this stream
    let tx = spawn_stream_task(send, recv);

    self.streams.lock().insert(stream_id, StreamHandle { send, tx });
    self.pane_streams.lock().insert(pane_id, stream_id);

    // Send binding PDU
    self.send_pdu(Pdu::BindPaneToStream(BindPaneToStream { pane_id }), stream_id).await?;

    Ok(stream_id)
}

// Route PDU to appropriate stream
async fn send_pdu(&self, pdu: Pdu, pane_id: Option<PaneId>) -> Result<()> {
    let stream_id = if let Some(pane_id) = pane_id {
        self.pane_streams.lock().get(&pane_id).copied().unwrap_or(StreamId(0))
    } else {
        StreamId(0)  // Session-level PDUs use stream 0
    };

    let handle = self.streams.lock().get(&stream_id)?;
    handle.tx.send(OutgoingPdu { pdu, serial }).await?;
    Ok(())
}
```

**Stream task (one per stream):**
```rust
fn spawn_stream_task(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream
) -> Sender<OutgoingPdu> {
    let (tx, rx) = channel();

    smol::spawn(async move {
        loop {
            futures::select! {
                // Send outgoing PDUs
                msg = rx.recv().fuse() => {
                    match msg {
                        Ok(OutgoingPdu { pdu, serial }) => {
                            pdu.encode_async(&mut send, serial).await?;
                            send.flush().await?;
                        }
                        Err(_) => break,
                    }
                }
                // Receive incoming PDUs
                pdu = Pdu::decode_async(&mut recv, None).fuse() => {
                    match pdu {
                        Ok(decoded) => {
                            // Process response/notification
                            process_incoming_pdu(decoded);
                        }
                        Err(_) => {
                            log::debug!("Stream closed");
                            break;
                        }
                    }
                }
            }
        }
        // Task terminates, stream cleaned up
    }).detach();

    tx
}
```

### QUIC Server Changes

**Location:** `wezterm-mux-server/src/quic_server.rs`

**Connection handler (accept multiple streams):**
```rust
smol::spawn(async move {
    let session_handler = Arc::new(Mutex::new(SessionHandler::new()));

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                let stream_id = send.id();
                let handler = Arc::clone(&session_handler);

                // Spawn task per stream
                smol::spawn(async move {
                    if let Err(e) = process_quic_stream(stream_id, send, recv, handler).await {
                        log::error!("Stream {} error: {}", stream_id, e);
                    }
                }).detach();
            }
            Err(e) => {
                log::info!("Connection ended: {}", e);
                break;
            }
        }
    }
}).detach();
```

**Stream task:**
```rust
async fn process_quic_stream(
    stream_id: StreamId,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    handler: Arc<Mutex<SessionHandler>>,
) -> Result<()> {
    let (tx, rx) = channel();
    handler.lock().register_stream(stream_id, tx.clone());

    loop {
        futures::select! {
            // Send responses/notifications for this stream
            item = rx.recv().fuse() => {
                match item {
                    Ok(OutgoingPdu { pdu, serial }) => {
                        pdu.encode_async(&mut send, serial).await?;
                        send.flush().await?;
                    }
                    Err(_) => break,
                }
            }
            // Process requests from client
            pdu = Pdu::decode_async(&mut recv, None).fuse() => {
                match pdu {
                    Ok(decoded) => {
                        handler.lock().process_one(stream_id, decoded);
                    }
                    Err(_) => {
                        log::debug!("Stream {} closed", stream_id);
                        break;
                    }
                }
            }
        }
    }

    handler.lock().unregister_stream(stream_id);
    Ok(())
}
```

### SessionHandler Changes

**Location:** `wezterm-mux-server-impl/src/sessionhandler.rs`

**New state:**
```rust
pub struct SessionHandler {
    // ... existing fields ...

    // New: Track pane→stream bindings
    pane_streams: HashMap<PaneId, StreamId>,

    // New: Send channels for each stream
    stream_senders: HashMap<StreamId, Sender<OutgoingPdu>>,
}
```

**Handle BindPaneToStream:**
```rust
fn process_one(&mut self, stream_id: StreamId, decoded: DecodedPdu) {
    match decoded.pdu {
        Pdu::BindPaneToStream(bind) => {
            log::debug!("Binding pane {} to stream {}", bind.pane_id, stream_id);
            self.pane_streams.insert(bind.pane_id, stream_id);
            // No response needed
        }
        // ... other PDUs ...
    }
}
```

**Route server-initiated PDUs:**
```rust
fn send_pdu(&self, pdu: Pdu, pane_id: Option<PaneId>, serial: u64) -> Result<()> {
    let stream_id = if let Some(pane_id) = pane_id {
        self.pane_streams.get(&pane_id).copied().unwrap_or(StreamId::ZERO)
    } else {
        StreamId::ZERO  // Session-level
    };

    let tx = self.stream_senders.get(&stream_id)
        .ok_or_else(|| anyhow!("Stream {} not found", stream_id))?;

    tx.send(OutgoingPdu { pdu, serial })?;
    Ok(())
}
```

**Stream lifecycle:**
```rust
fn register_stream(&mut self, stream_id: StreamId, tx: Sender<OutgoingPdu>) {
    self.stream_senders.insert(stream_id, tx);
}

fn unregister_stream(&mut self, stream_id: StreamId) {
    self.stream_senders.remove(&stream_id);

    // Rebind affected panes to stream 0
    let affected_panes: Vec<PaneId> = self.pane_streams
        .iter()
        .filter(|(_, &sid)| sid == stream_id)
        .map(|(&pane_id, _)| pane_id)
        .collect();

    for pane_id in affected_panes {
        self.pane_streams.remove(&pane_id);
        log::debug!("Pane {} falling back to stream 0", pane_id);
    }
}
```

### TLS Compatibility

**No changes required to TLS implementation:**

**Client (`wezterm-client/src/client.rs`):**
- `client_thread_async` unchanged - uses single `Box<dyn AsyncReadAndWrite>`
- Receives `BindPaneToStream` PDU: processed but has no effect
- All panes use stream 0 (the one TCP connection)

**Server (`wezterm-mux-server-impl/src/dispatch.rs`):**
- `dispatch::process()` unchanged
- `SessionHandler` tracks `BindPaneToStream` but only has stream 0
- All routing returns stream 0

**Model:** TLS is multi-stream with N=1 (stream 0 only)

---

## Error Handling

### Stream Closure

**Detection:** `decode_async` or `encode_async` returns error

**Action:**
- Stream task loop exits
- Task terminates
- Server: `unregister_stream()` rebinds panes to stream 0
- Client: Remove stream from tracking, rebind panes to stream 0

**Recovery:** Continue on stream 0 (graceful degradation)

### Connection Closure

**Detection:** Quinn returns `ConnectionError::LocallyClosed`

**Action:**
- All streams fail simultaneously
- All stream tasks terminate
- Connection handler loop exits
- Client: Reconnection logic (existing)

**Cleanup:** Automatic via task termination

### Stream Limit Exhaustion

**Detection:** `connection.open_bi()` returns error

**Action:**
- Log warning
- Use stream 0 (multiplex onto primary stream)
- Continue normally

**Mitigation:** QUIC stream limits are typically high (100+)

---

## Performance Considerations

### Stream Creation Overhead

**Cost:** Minimal - QUIC streams are lightweight
- No handshake required
- Just stream ID allocation and local state
- Reference: QUIC spec designed for cheap stream creation

**Policy:** Create freely, one per pane

### Memory Overhead

**Per stream:**
- Send/recv buffers (configurable, typically 256KB default)
- Stream state (stream ID, sequence numbers, flow control)

**For 100 panes:** ~50MB additional (acceptable for typical use)

### Congestion Control

**QUIC behavior:**
- Single connection-level congestion window
- Streams share bandwidth fairly
- No per-stream congestion control

**Implication:** High-output pane won't starve others (QUIC scheduler is fair)

---

## Migration Plan

### Phase 1: Protocol Support (Both Sides)

1. Add `BindPaneToStream` PDU to codec
2. Bump codec version (requires matching client/server)
3. SessionHandler tracks bindings (no-op for TLS)

### Phase 2: Server Multi-Stream

1. Accept multiple streams concurrently
2. Spawn task per stream
3. Route PDUs by pane binding
4. Test with single-stream clients (should work - stream 0)

### Phase 3: Client Multi-Stream

1. Open stream per pane on creation
2. Send `BindPaneToStream` after `SpawnV2`
3. Route outgoing PDUs by pane
4. Test with TLS (should be no-op)

### Phase 4: Reconnection Enhancement

1. After `ListPanes`, selectively rebind panes
2. Heuristic: Active panes get dedicated streams
3. Inactive panes stay on stream 0

### Phase 5: Optimization

1. Metrics: Track stream utilization
2. Dynamic rebinding: Move high-traffic panes to dedicated streams
3. Stream pooling: Reuse streams for closed panes

---

## Testing Strategy

### Unit Tests

- `BindPaneToStream` serialization/deserialization
- Routing logic (pane ID → stream ID lookup)
- Stream registration/unregistration

### Integration Tests

- Multi-pane creation on QUIC
- TLS with multi-pane (verify no-op)
- Stream closure and rebinding
- Reconnection with pane rebinding

### Load Tests

- 100 panes, mixed output patterns
- High-output pane vs interactive pane latency
- Stream limit exhaustion
- Connection closure with many streams

### Compatibility Tests

- QUIC multi-stream client ↔ QUIC multi-stream server
- TLS client ↔ TLS server (unchanged)
- Mixed version (should fail cleanly via codec version)

---

## Open Questions & Future Work

### 1. Pane Rebinding Heuristics

**Question:** When to automatically create new streams on reconnect?

**Options:**
- All panes get streams (simple, wastes resources)
- Active panes only (requires activity tracking)
- Manual via UI (flexible, requires UX design)

**Recommendation:** Start with "on-demand" - create stream when pane becomes active

### 2. Stream Limit Handling

**Question:** What if `open_bi()` fails?

**Answer:** Fall back to stream 0, log warning

**Future:** Implement stream pooling (reuse closed streams)

### 3. Metrics & Observability

**Useful metrics:**
- Streams per connection
- Bytes per stream
- Stream creation/closure rate
- Pane rebinding events

**Future:** Expose via debug UI or logging

### 4. Stream Priorities

**QUIC supports stream priorities** - could prioritize interactive panes

**Future work:** Add priority to `BindPaneToStream`, configure QUIC stream priority

---

## References

### Code Locations

- **Codec:** `codec/src/lib.rs`
- **QUIC Client:** `wezterm-client/src/quic_client.rs`
- **QUIC Server:** `wezterm-mux-server/src/quic_server.rs`
- **TLS Server:** `wezterm-mux-server/src/ossl.rs`
- **Dispatcher:** `wezterm-mux-server-impl/src/dispatch.rs`
- **SessionHandler:** `wezterm-mux-server-impl/src/sessionhandler.rs`
- **Client Thread:** `wezterm-client/src/client.rs`

### Key Findings

- Serial numbers: Request/response pairing only (wezterm-client/src/client.rs:482-562)
- Pane creation: Independent objects (wezterm-mux-server-impl/src/sessionhandler.rs:712-726)
- Stream IDs: Via `SendStream::id()` / `RecvStream::id()` (quinn crate)
- Reconnection: `ListPanes` + mark-and-sweep (wezterm-client/src/domain.rs:510-714)
- Error handling: Stream/connection closure terminates tasks automatically

---

## Implementation Plan

### Architecture Overview

Stream IDs are implicit in the transport layer and never appear in the wire protocol.

- **Wire Protocol**: `BindPaneToStream(pane_id)` sent ON the target stream (stream implicit)
- **Internal Type**: `struct StreamId(u64)` wrapper around quinn stream index for clarity
- **QUIC Boundary**: Extract via `StreamId(send.id().index())`
- **TLS Model**: Always uses `StreamId(0)` (single stream)
- **Routing**: `HashMap<PaneId, StreamId>` and `HashMap<StreamId, PduSender>`

### Commit Sequence (22 commits across 5 phases)

#### Phase 1: Protocol Foundation (3 commits)

1. **Add internal StreamId type** (`wezterm-mux-server-impl/src/lib.rs`)
   - Define `pub struct StreamId(pub u64)`
   - Derive: Debug, Copy, Clone, Eq, PartialEq, Hash
   - Not in codec - internal to mux implementation

2. **Add BindPaneToStream PDU** (`codec/src/lib.rs`)
   - Add struct: `pub struct BindPaneToStream { pub pane_id: PaneId }`
   - Add to Pdu enum: `BindPaneToStream(BindPaneToStream): 65`
   - Add serialization tests

3. **Bump codec version** (`codec/src/lib.rs`)
   - Change `CODEC_VERSION` from 46 → 47 (breaking change)

#### Phase 2: Server Multi-Stream (8 commits)

4. **Add stream tracking to SessionHandler** (`wezterm-mux-server-impl/src/sessionhandler.rs`)
   - Add fields: `pane_streams: HashMap<PaneId, StreamId>`
   - Add fields: `stream_senders: HashMap<StreamId, PduSender>`

5. **Handle BindPaneToStream PDU** (`wezterm-mux-server-impl/src/sessionhandler.rs`)
   - Add `stream_id: StreamId` parameter to `process_one()`
   - Match and insert into `pane_streams` map

6. **Implement pane→stream routing** (`wezterm-mux-server-impl/src/sessionhandler.rs`)
   - Look up `pane_streams[pane_id]`, default to `StreamId(0)`
   - Route responses/notifications to correct `stream_senders[stream_id]`

7. **Add stream registration/unregistration** (`wezterm-mux-server-impl/src/sessionhandler.rs`)
   - `register_stream(stream_id, tx)` - add to stream_senders
   - `unregister_stream(stream_id)` - remove bindings, rebind to StreamId(0)

8. **Wrap SessionHandler for concurrency** (`wezterm-mux-server/src/quic_server.rs`)
   - Change to `Arc<Mutex<SessionHandler>>`
   - Lock per operation in `process_quic_stream()`

9. **Accept multiple streams concurrently** (`wezterm-mux-server/src/quic_server.rs`)
   - Refactor connection handler to spawn task per stream instead of sequential

10. **Wire stream registration** (`wezterm-mux-server/src/quic_server.rs`)
    - In `process_quic_stream()`: extract `StreamId(send.id().index())`
    - Call `register_stream()` on entry, `unregister_stream()` on exit
    - Pass stream_id to `process_one()`

11. **Server integration tests** (`wezterm-mux-server-impl` tests)
    - Test BindPaneToStream routing
    - Test multiple concurrent streams
    - Test stream closure and fallback

#### Phase 3: Client Multi-Stream (5 commits)

12. **Add QuicConnectionState** (`wezterm-client/src/quic_client.rs`)
    - New struct with `connection`, `streams`, `pane_streams` fields
    - `StreamHandle` with send channel

13. **Client stream management** (`wezterm-client/src/quic_client.rs`)
    - `open_pane_stream(pane_id)` - open_bi(), extract StreamId, spawn task
    - `send_pdu()` - route by pane binding, default to StreamId(0)

14. **Integrate with pane creation** (pane creation code)
    - After SpawnV2/SplitPane response: `open_pane_stream(pane_id)`
    - Sends `BindPaneToStream` on new stream

15. **Stream closure fallback** (`wezterm-client/src/quic_client.rs`)
    - On stream error: remove from maps, rebind panes to StreamId(0)

16. **Client unit tests** (`wezterm-client` tests)
    - Test stream opening and binding
    - Test PDU routing
    - Test fallback

#### Phase 4: Reconnection (2 commits)

17. **Re-establish streams on reconnect** (reconnection logic)
    - After ListPanes response: open stream per pane
    - Send BindPaneToStream for each

18. **Reconnection integration test**
    - Connect, create panes, disconnect, reconnect
    - Verify streams re-established

#### Phase 5: Config & Testing (4 commits)

19. **Runtime config option**
    - Add `quic_use_multiple_streams: bool` (default: true)
    - When false, skip stream opening (use StreamId(0) only)

20. **Multi-pane concurrency tests**
    - High-output pane + interactive pane
    - Verify head-of-line blocking avoided

21. **Stream closure recovery tests**
    - Force close stream, verify fallback
    - Verify pane continues on StreamId(0)

22. **TLS compatibility regression tests**
    - BindPaneToStream received but ignored
    - All traffic on StreamId(0)
    - No behavioral changes

### Key Implementation Notes

**No StreamId in codec layer**: Stream IDs are implicit in QUIC framing, never serialized.

**Absence from map means StreamId(0)**: If pane not in `pane_streams`, route to stream 0.

**StreamId(0) is real**: First client-initiated bidirectional stream; not a sentinel value.

**Stream closure handling**: `unregister_stream()` finds and removes affected bindings, panes fall back to stream 0 gracefully.

**Lock contention**: `Arc<Mutex<SessionHandler>>` shared across concurrent stream tasks. Monitor performance; if problematic, consider per-pane locking or message passing.

**Config disables feature**: When `quic_use_multiple_streams = false`, skip stream opening; all panes use StreamId(0) like TLS mode.

### Validation Strategy

**Per commit**:
- `cargo check -p <affected_package>`
- `cargo test -p <affected_package>` (where tests added)
- No new warnings

**Final validation**:
- `cargo check` (workspace)
- `cargo test` (workspace)
- Manual: 5+ panes, mixed output, verify isolation
- Manual: Reconnection preserves panes
- Manual: TLS unchanged

---

## Conclusion

Multi-stream QUIC is **feasible and recommended** for wezterm mux:

✅ Protocol supports out-of-order delivery (serial numbers are just pairing)

✅ Independent pane objects map naturally to independent streams

✅ Simple binding model (`BindPaneToStream` PDU) avoids complex inference

✅ Graceful degradation via stream 0 fallback

✅ TLS compatibility via single-stream model (N=1)

✅ Automatic cleanup via Quinn connection/stream lifecycle

**Risk:** Moderate implementation complexity

**Benefit:** Eliminates head-of-line blocking for interactive panes

**Recommendation:** Proceed with phased implementation starting with protocol support.
