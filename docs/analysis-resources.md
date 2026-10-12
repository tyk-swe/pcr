# Analysis resource and evidence contracts

Selection follows capture-global IP reconstruction/conversation indexing and
precedes TCP dispatch/collectors. Filtered frames still charge input, scope,
and index budgets; prefilter the file when those costs must shrink.

Scoped tuples are conversations, not connection epochs. TLS sessions identify
emitted handshakes; follow `direction_generation` distinguishes reuse/eviction without
inventing handshakes. Capture-wide interface/scope IDs differ from source-local
section/interface IDs. Endpoint/port/protocol aggregates are capture-wide.

IP expiry sees every physical timestamp; TCP sees selected frames. A filter may
hide a clock jump from TCP, not the global report. Capture-order high-water time
never rewinds on rollback; forward outliers can expire state/pin time until it
catches up. Reports retain rollback magnitude/largest forward step/frame, not a
malformation judgment. Out-of-range time fails typed. I/O bucket origin is first
matched time; earlier frames increment `underflow_frames` and enter bucket zero.

## What the ceilings cover

Reader `max_interfaces` counts all descriptions per PCAPNG section, even unused/
filtered ones; `ReaderLimits::max_total_interfaces` independently bounds the capture.
Normalization may reduce output interfaces, never input costs. Options-per-block
(default 1,024) limits decoded option allocations beyond encoded block size;
excess fails `policy.capture_stream_limit`.

| Retention | Bound and lifetime |
| --- | --- |
| Physical input | `max_frames` and `max_bytes` count all physical frames/payload bytes, including filtered frames. Reader block/frame and interface limits apply separately. |
| Conversation indices | At most `max_flows` distinct scoped tuples **per transport** over the entire capture. Payload expiry does not remove these keys. TLS's distinct-observation set is bounded by the same IDs. |
| Scope paths | `max_scope_bytes` charges both retained path copies and conservative table/header capacity. Output shares immutable paths. Count is also bounded from the physical frame ceiling. This is a retained metadata charge, not allocator accounting. |
| IP state | `max_ip_reassembly_bytes` covers retained fragments, reconstruction/cascade buffers and charged metadata; per-datagram, fragment and retained-outcome limits also apply. |
| TCP state | `max_tcp_reassembly_bytes` covers retained payload/history and charged flow/segment metadata. Per-direction byte/segment ceilings and capture-time idle expiry are independent. |
| HTTP/2 state | Frames and admitted HTTP/2 streams are bounded across the capture; active streams (including reserved streams) per connection; payload bytes per frame; compressed/decoded bytes, fields, and CONTINUATION count per header block; HPACK table bytes and pending SETTINGS per direction; body bytes per message. HPACK decoding reserves finite scratch space for table growth and decoded fields. Application limits separately bound aggregate live state, cumulative retained evidence, and provenance. |
| TLS state | `max_tls_sessions` bounds live/closed tracking slots; `max_tls_buffer_bytes` bounds logical handshake-buffer lengths and alert charges, not parsed hello summaries or allocation capacity. A direction has a 135,168-byte logical buffer ceiling. Parser and session-count limits bound retained summaries separately. Terminal paths release recorded charges. |
| Stats | Only the selected table allocates aggregation entries in the CLI. Library `Table::All` intentionally retains all tables. `--top` caps final rows, not keys needed to compute exact counts. The protocols, conversations, endpoints, and ports tables keep their busiest rows by frame count, breaking ties by bytes (protocols: by name), and list them busiest first; `io` keeps its first buckets in time order. |
| Results | JSON retains selected rows/sessions/chunks according to command limits. TLS output retention is independent of active state. NDJSON holds one prepared line per encoder, at most 16 MiB including newline. |
| Native/progress work | Offline analysis uses no native capture queue. Live capture can additionally retain its bounded native queue. A blocked output/callback worker retains its permit and captures until cleanup actually ends. `Runtime::snapshot()` exposes active, rejected, and retained capacity from timed-out or cancelled waits. |

Cleartext HTTP/2 uses prior knowledge/h2c, not TLS decryption. TCP selectors and
HTTP/2 stream IDs differ. Final connections/later issues can qualify earlier
messages, including `goaway_unprocessed`. Sources are direct physical contributors;
`compression_sources` also cites prior HPACK dictionary contributors. DATA bodies
are counted/discarded. EOF-incomplete connections differ from eviction; clean
closed tuple reuse does not invalidate an earlier generation.
Incomplete/refused h2c keeps exact HTTP/1 bytes/sources without invented stream 1;
captured 101 permits a real stream 1 request, even incomplete. Head/chunk/trailer
scratch and retained failure evidence stay bounded.

Peak memory includes input/decode, indexed metadata, IP/TCP/TLS, collector,
retained results, serialization, runtime/native stacks, transient copies, and
allocator overhead. Default TLS's four major charges alone total 400 MiB:
TCP 256 MiB, IP 64 MiB, TLS 64 MiB, and scope 16 MiB. This is neither reservation nor RSS cap; hex strings
alone need about 2×payload bytes.

`max_bytes` counts frame payload, not headers/options. A bare `Reader` bounds records/
interfaces/metadata while seeking frames; CLI `compression::Input` additionally
bounds cumulative encoded/decoded bytes including metadata. Embedders needing
those ceilings use the wrapper; hard I/O limits belong outside the reader.
TLS hello completion is observed assembly, not authentication/complete negotiation
validation; first ClientHello remains the retry fingerprint source.

No allocator-wide cap is promised. Encoders prepare bounded records atomically,
but OS write/flush can fail partway; no completion is acknowledged. Invocation
remaining time clips writer wait/lock polling (1 ms). Serialization checks on
return; arbitrary `Read`/`Write`/providers/callbacks/destructors are not preemptible.
Timeout can end a wait before actual cleanup. Scheduled capture/pacing checks
are ≤25 ms, excluding native/scheduler overshoot.

## HTTP/2 limits

| Flag | Default | Hard ceiling | Scope |
| --- | --- | --- | --- |
| `--max-http2-frames` | 100,000 | 1,000,000 | Whole run |
| `--max-http2-streams` | 4,096 | 100,000 | Whole run, including generations |
| `--max-http2-active-streams` | 128 | 4,096 | Per connection, including reserved and prelude |
| `--max-http2-frame-bytes` | 1 MiB | 16,777,215 | Per frame payload |
| `--max-http2-header-block-bytes` | 64 KiB | 16 MiB | Per compressed block |
| `--max-http2-header-bytes` | 64 KiB | 16 MiB | Per decoded list, including overhead |
| `--max-http2-headers` | 256 | 16,384 | Per block |
| `--max-http2-table-bytes` | 64 KiB | 16 MiB | Per direction |
| `--max-http2-continuations` | 256 | 16,384 | Per block |
| `--max-http2-pending-settings` | 64 | 4,096 | Per direction |
| `--max-http2-body-bytes` | 16 MiB | 256 MiB | Per message |

Configuration values must be nonzero. Legal protocol SETTINGS values of zero
remain legal. These limits supplement, rather than replace, shared
application/capture/output budgets and do not constitute a process-RSS
ceiling.

## Example captures

Two small published captures exercise the clock and scope evidence described
above, and the checked-in `stats` documents are generated from them:

```sh
packetcraftr --output json stats examples/captures/clock-regression.pcap \
  --table io --interval-ms 1000   # examples/documents/output-stats-clock.json
packetcraftr --output json stats examples/captures/scoped-vxlan.pcap \
  --table conversations           # examples/documents/output-stats-scopes.json
```

`clock-regression.pcap` carries a 100/90/101-second timestamp sequence, so the
report shows one regression, the largest forward step, and an I/O bucket origin
with one underflow frame. `scoped-vxlan.pcap` carries TCP conversations under
two VXLAN network identifiers, so conversation rows expose scope identifiers and
ordered encapsulation metadata. The release archive verifier runs both examples
and checks that their output equals the packaged JSON documents.

## Interpreting loss and empty results

| Evidence | Interpretation |
| --- | --- |
| `sessions == 0`, completed invocation | No assembled TLS was observed; inspect `tcp_streams` and `udp_443_frames`. |
| `sessions > 0`, `sessions_selected == 0` | Session selectors excluded the assembled sessions. |
| `sessions_evicted` / `buffer_limit_hits` | Analysis lost active state to a resource ceiling; session statuses preserve domain evidence. |
| `sessions_omitted` / omission diagnostics | Analysis ran, but aggregate output retention excluded results. |
| IP incomplete/eviction counters and omitted outcomes | Capture-global fragment evidence, independent of presentation filtering. |
| Terminal `error` / `io.output_record_limit` / `io.cancelled` | Invocation is incomplete. Earlier records remain useful but are not a complete answer. |
| Partial bytes with no terminal record | Output is incomplete; do not infer success from a process or schema-valid prefix. |

The configured CLI flags and typed library errors identify the corresponding
ceilings. These counters and codes are the canonical loss evidence;
resource metadata adds no second loss taxonomy.

## Effective settings and resource ownership

--resource-diagnostics on JSON/NDJSON adds resolved settings (value/unit/stage/
scope/enabled/source: default, preset, override, derived, fixed) from executing
arguments. [Stats](../examples/documents/output-stats-resources.json) and
[read](../examples/documents/output-read-resources.json) examples use full-native
Linux. Worker supported means compiled owner, not available device/privilege.
NDJSON samples first/terminal records; failed output promises no final snapshot.

--output-timeout-ms bounds each write/flush acknowledgment, clipped by operation
time. Terminal error cleanup has a separate fixed 1,000 ms allowance and never retries
a failed stream. One record is in flight; serialization/arbitrary writers remain
cooperative. Response windows are not output deadlines.

Client:: new has an isolated Runtime; with_runtime shares admission among clients.
Snapshot tracks active/rejected/retained cleanup capacity. Timed-out/cancelled
callbacks and captured destructors retain permits through cleanup.
Netio `resources::native_snapshot` reports the shared 16-slot capture/route/TCP pool;
`tcp_connect_snapshot` is nested connect admission. Neither counts all OS threads,
handles, or RSS.

## TCP pending ranges

Out-of-order ranges charge 4 KiB pages/slack and interval metadata under sequence
and aggregate ceilings; sparse input can reject earlier than payload-only budgets.
Incoming bytes copy once; delivery flattens once. N adjacent 100-byte segments after
a missing byte hold `ceil((100N+1)/4096)` pages, linear growth. Admission includes
old storage coexisting with output/history; trimmed history still charges its
allocation. Tests assert copy/allocation counts independently. Charges are not RSS.

## Hosting untrusted captures with a hard stop

Run each untrusted analysis in its own OS-limited process when a hard memory or
execution stop is required. On a system with delegated user cgroups, for example:

```sh
systemd-run --user --wait --pipe \
  -p MemoryMax=512M -p MemorySwapMax=0 -p TasksMax=32 -p RuntimeMaxSec=60s \
  -p KillMode=control-group -p KillSignal=SIGKILL \
  ./target/release/packetcraftr --output ndjson --resource-diagnostics \
  tls CAPTURE.pcap --max-duration-ms 55000
```

Provision cgroup permissions and verify those limits in the deployment. A
supervisor should constrain filesystem access, disable networking for offline
workers, capture exit status, and terminate the worker process/cgroup when the
outer deadline expires. Memory/CPU/task limits and wall-clock termination solve
different problems. Allow for serialization, allocator and runtime overhead
alongside configured state ceilings. Never treat a killed worker's output prefix
as complete; keep it marked incomplete unless its terminal record was
acknowledged and the invocation succeeded. In-process providers, generic `Read`,
serialization and callbacks remain cooperative.

## Composed invocation and forwarding bounds

[Resource presets](resource-presets.md) own the named defaults, and the
[verification contract](verification-contract.md) owns forwarding accounting.
Resource diagnostics for `verify-forwarding` include the requirements from both
rules and selection filters. Semantic fuzz targets and deterministic contract
tests guard verdict/detail invariance separately from the process measurements
above.
