# Analysis resource and evidence contracts

Input selection (`analysis::Options::filter`; its rustdoc says what each kind
of predicate preserves) occurs after capture-global IP reconstruction and
conversation indexing, and before TCP dispatch and collectors. Filtered-out
frames still consume physical-input, scope, and index budgets. Pre-filter the
capture file itself when those costs must be reduced.

A scoped tuple is a conversation, not a TCP connection epoch. TLS `session` is
unique per emitted handshake. Follow `direction_generation` separates delivery
state across reuse and eviction; it does not infer an unseen handshake. Scope
metadata uses the reader's capture-wide interface numbering across sections;
source-local section/interface identifiers remain on capture records. Endpoint,
port and protocol tables are capture-wide aggregates; conversation rows identify
their exact domains.

IP expiry follows every physical frame; TCP applies the same clock policy to
selected frames. Thus a filter can hide a clock jump from TCP while it remains
in the capture-global clock report. Capture time drives expiry in capture order,
across interfaces. The first physical timestamp anchors the clock; subsequent
offsets advance a high-water mark. A rollback cannot rewind it. A forward
outlier can expire state immediately and pin expiry until later timestamps
catch up. Clock reports include filtered input, rollback counts/magnitudes and
the largest forward step with its frame. A forward step is evidence, not an
assertion that a legitimate capture gap is malformed. Out-of-range instants
fail with a typed timestamp error. I/O buckets use their separately reported
first-observed matched `origin`; earlier timestamps are counted in
`underflow_frames` and folded into bucket zero.

## What the ceilings cover

`--max-interfaces` counts interface descriptions per input PCAPNG section,
including unused interfaces and interfaces whose frames are filtered out. The
capture-wide input ceiling is `ReaderLimits::max_total_interfaces`. Under
`read --normalize`, filtering can reduce the selected output interface count,
never either input count. Non-normalizing reads and rewrites keep the
per-section input semantics.

| Retention | Bound and lifetime |
| --- | --- |
| Physical input | `max_frames` and `max_bytes` count all physical frames/payload bytes, including filtered frames. Reader block/frame and interface limits apply separately. |
| Conversation indices | At most `max_flows` distinct scoped tuples **per transport** over the entire capture. Payload expiry does not remove these keys. TLS's distinct-observation set is bounded by the same IDs. |
| Scope paths | `max_scope_bytes` charges both retained path copies and conservative table/header capacity. Output shares immutable paths. Count is also bounded from the physical frame ceiling. This is a retained metadata charge, not allocator accounting. |
| IP state | `max_ip_reassembly_bytes` covers retained fragments, reconstruction/cascade buffers and charged metadata; per-datagram, fragment and retained-outcome limits also apply. |
| TCP state | `max_tcp_reassembly_bytes` covers retained payload/history and charged flow/segment metadata. Per-direction byte/segment ceilings and capture-time idle expiry are independent. |
| TLS state | `max_tls_sessions` bounds live/closed tracking slots; `max_tls_buffer_bytes` bounds logical handshake-buffer lengths and alert charges, not parsed hello summaries or allocation capacity. A direction has a 135,168-byte logical buffer ceiling. Parser and session-count limits bound retained summaries separately. Terminal paths release recorded charges. |
| Stats | Only the selected table allocates aggregation entries in the CLI. Library `Table::All` intentionally retains all tables. `--top` caps final rows, not keys needed to compute exact counts. |
| Results | JSON retains selected rows/sessions/chunks according to command limits. TLS output retention is independent of active state. NDJSON holds one prepared line per encoder, at most 16 MiB including newline. |
| Native/progress work | Offline analysis uses no native capture queue. Live capture can additionally retain its bounded native queue. A blocked output/callback worker retains its permit and captures until cleanup actually ends. `Runtime::snapshot()` exposes active, rejected, and timed-out retained capacity. |

A useful peak estimate is **input/decode + indexed metadata + IP + TCP + TLS +
selected collector + retained results + serialization + runtime/native overhead**,
including only the stages that the command enables. At default TLS settings the
four principal state charges alone can total 400 MiB: TCP 256, IP 64, TLS 64 and
scope 16. This is neither a reservation nor an RSS cap. Index tables, decoded
layers, result ownership, thread stacks, allocator overhead and transient copies
coexist. For a frame of B bytes, a hex output field alone needs about 2B string
bytes before bounded NDJSON serialization begins. Raising JSON retention can
increase memory even while active TLS state stays fixed.

The `max_bytes` limit counts payload bytes, not container headers, options or
metadata. A bare library `capture_file::Reader` bounds each record, interface
set and metadata block (PCAPNG metadata limits apply while seeking the next
frame, not to the whole input). The CLI wraps its source in
`capture_file::compression::Input`, which enforces cumulative encoded and
decoded bytes including metadata; library hosts that need that ceiling use the
same wrapper. A hard I/O-work ceiling must be enforced outside the reader.
Invocation and phase deadlines reach Reader metadata/EOF boundaries but remain
cooperative around blocking I/O. TLS hello completion means assembly of the
observed client/server hellos, not authentication or validation of every
negotiation constraint; the first ClientHello remains the fingerprint source
after a retry.

There is no global allocator framework or process-RSS promise. The encoder
prepares records atomically, but an OS writer can still fail halfway through
`write_all` or at flush. It then fails closed and never acknowledges completion.
Max-duration NDJSON commands also bind an encoder publisher to their remaining
operation duration. Lock polling is cooperative (1 ms); serialization is checked
on return, and writer waiting is clipped to the smaller remaining duration and
per-write timeout. The original encoder owner can attempt a terminal error under
a separate allowance (see `--output-timeout-ms` below). Direct arbitrary `Write`
implementations are not preemptible. Capture/exchange response windows are not
output deadlines. A caller's workflow deadline bounds its wait for callbacks; the
callback itself, serialization and its destructor may finish later. Generic
`Read` and providers must return before their next cooperative check. Capture
polling and cancellable pacing check at intervals of at most 25 ms while
scheduled, excluding provider overshoot and scheduler delays.

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
ordered encapsulation metadata. A CLI contract test keeps both documents equal
to the current output.

## Reproducing measurements

Build the portable CLI with `cargo build --locked --release -p packetcraftr-cli
--no-default-features`, then run `python3 scripts/measure-analysis.py` for
release-profile CLI measurements (`--sizes` sets the workload cardinalities).
It generates unique flows, tiny reverse-ordered TCP segments, retransmissions,
reverse fragments, VNI scopes, TLS gaps, and adjacent and reverse TCP growth
(`tcp-growth`, `tcp-growth-reverse`). It measures read, follow, TLS, HTTP source
tracking, selected/filtered stats, forwarding with and without retained details,
file/pipe input and intentional limit failures. `read` supports NDJSON, not
aggregate JSON; TLS and stats exercise aggregate output where supported.

`target/analysis-measurements/report.json` records the binary path and SHA-256,
version, compiler, and, per measurement, the exact command, workload and
cardinality, physical frame count, input bytes, exit code, time and peak RSS.
Per-command help files preserve the effective defaults. Setup is outside the
timed child; process startup and output to `/dev/null` are inside.

Pass `--heaptrack` for **separate** allocator-profile runs, or run a focused
`heaptrack -o PROFILE target/release/packetcraftr ...` and inspect it with
`heaptrack_print -f PROFILE.zst`. RSS measurements exclude profiler overhead.
Allocator “unfreed at exit” includes process-lifetime state and is not proof of
an operation leak; engine and callback cleanup tests check their own ownership.
Do not interpret a process that has exited as an in-process heap-retention sample.
Shared-runner timings are observations, not performance gates. Keep full report
files with the binary digest when comparing versions.

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

Use `--resource-diagnostics` with `--output json` or `--output ndjson` to add a
`resources` member to the existing envelope. Settings report their resolved
value, unit, stage, scope, whether the stage is enabled, and source (`default`,
`preset:NAME`, `override`, `derived`, or `fixed`). They are read from the same
argument definitions and parsed values that execute the command.
The [stats resource example](../examples/documents/output-stats-resources.json)
and [read resource example](../examples/documents/output-read-resources.json)
were generated with the Linux full-native profile. A worker's `supported` field
identifies its compiled resource owner, not device availability or permissions.
NDJSON includes settings and worker samples on the first and terminal records,
without inserting extra events. A failed writer cannot publish a trustworthy
final snapshot or completion, even if it later finishes writing a partial line.

`--output-timeout-ms` (range and default in `--help`) bounds each NDJSON
write/flush acknowledgment; the remaining operation deadline takes precedence.
Terminal-error cleanup uses a separate fixed 1,000 ms allowance
(`terminal_error_timeout_ms` in the diagnostics); it never retries an already
failed output stream. One record remains in flight at a time. This option does
not make synchronous serialization or an arbitrary writer preemptible.

Embedders can clone a `runtime::Runtime` and give it to multiple clients with
`Client::with_runtime`; `Client::runtime` returns it and `Runtime::snapshot()`
reports its retained capacity. `Client::new` creates an isolated runtime.
Timed-out callbacks and their captured-resource destructors keep their permits
until cleanup ends. `packetcraftr_netio::resources::native_snapshot()` reports
the process-wide native worker pool (`resources::WORKER_CAPACITY`, 16 slots
shared by capture reads, route queries, and TCP connects): active reservations,
rejected admissions and retained cleanup. `tcp_connect_snapshot()` reports the
TCP connect sub-limit of the same pool. These counts describe admission
reservations, not all OS threads, handles, or process memory.

## TCP pending ranges

Pending out-of-order ranges use separately charged 4 KiB payload pages and
interval descriptors. A direction's sequence window bounds the number of pages;
the aggregate memory ceiling includes page storage/slack and metadata, so sparse
captures or tight aggregate limits can reject earlier than payload-only
accounting would. Adjacent and reverse growth do not copy retained bytes:
incoming pending payload is copied once, and delivery flattens an interval once
(one output allocation, one copy of the retained interval). N adjacent 100-byte
segments behind a missing first byte therefore hold
`ceil((100 × N + 1) / 4096)` pages, and growth is linear in N. Admission
accounts for old storage coexisting with prepared output/history. History keeps
and charges its allocation while trimming its logical retained tail. These
remain conservative charges, not RSS. Unit tests assert the copy and allocation
counts separately from timings.

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
