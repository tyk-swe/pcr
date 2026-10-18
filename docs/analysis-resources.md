# Analysis resource and evidence contracts

Selection follows capture-global IP reconstruction and conversation indexing and
precedes TCP dispatch and collectors. Filtered frames still charge input, scope,
and index budgets; prefilter the file when those costs must shrink.

Scoped tuples are conversations, not connection epochs. TLS sessions identify
emitted handshakes; follow `direction_generation` distinguishes reuse/eviction.
Capture-wide interface/scope IDs differ from source-local section/interface IDs.
IP expiry sees every physical timestamp; TCP sees selected frames. Capture-order
high-water time never rewinds on rollback; reports retain rollback magnitude and
largest forward step. I/O bucket origin is the first matched timestamp; earlier
frames increment `underflow_frames` and enter bucket zero.

## What the ceilings cover

Reader `max_interfaces` counts descriptions per PCAPNG section;
`ReaderLimits::max_total_interfaces` independently bounds the capture (default
1,024 options per block; excess fails `policy.capture_stream_limit`).

| Retention | Bound and lifetime |
| --- | --- |
| Physical input | `max_frames` and `max_bytes` count all physical frames and payload bytes, including filtered frames. CLI `compression::Input` also bounds encoded/decoded bytes including metadata. |
| Conversation indices | At most `max_flows` distinct scoped tuples **per transport** over the capture; expiry does not reclaim indices. |
| Scope paths | `max_scope_bytes` charges retained path copies and table/header capacity. |
| IP state | `max_ip_reassembly_bytes` covers retained fragments, cascade buffers, and metadata; per-datagram, fragment, and outcome limits also apply. |
| TCP state | `max_tcp_reassembly_bytes` covers retained payload/history, 4 KiB out-of-order page slack, and flow/segment metadata. |
| HTTP/2 state | Bounded frames, streams, active streams per connection, frame payload, compressed/decoded headers, continuations, HPACK table bytes, pending SETTINGS, and body bytes alongside shared application/provenance limits. |
| TLS state | `max_tls_sessions` bounds tracked slots; `max_tls_buffer_bytes` bounds logical handshake buffers (135,168-byte floor per direction) and alert charges. |
| Stats | CLI retains only selected tables; overview collects protocols/endpoints/conversations together, defaulting to five rows each. `--sort` ranks before `--top`; totals precede truncation. See [statistics](statistics.md). |
| Results | JSON retains selected rows/sessions/chunks up to command limits; NDJSON holds one line per encoder (at most 16 MiB including newline). |
| Native/progress work | Capture queues and unfinished native work remain bounded and charged. Progressive callback bodies/captures retain Runtime admission; thread-exit limitations are described below. |

Cleartext HTTP/2 analyzes prior knowledge and h2c (no TLS decryption); DATA
bodies are counted and discarded, and later connection issues (`goaway_unprocessed`)
can qualify earlier messages. Default TLS's four major logical charges total
400 MiB (TCP 256 MiB, IP 64 MiB, TLS 64 MiB, scope 16 MiB); logical charges are
not process RSS caps.

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

Configuration values must be nonzero; legal protocol SETTINGS values of zero
remain legal.

## Example captures

```sh
packetcraftr --output json analyze stats examples/captures/clock-regression.pcap \
  --table io --interval-ms 1000   # examples/documents/output-stats-clock.json
packetcraftr --output json analyze stats examples/captures/scoped-vxlan.pcap \
  --table conversations           # examples/documents/output-stats-scopes.json
```

`clock-regression.pcap` exercises a 100/90/101-second timestamp sequence
(regression, forward step, and underflow frame); `scoped-vxlan.pcap` exercises
VXLAN scope identifiers and encapsulation metadata.

## Interpreting loss and empty results

| Evidence | Interpretation |
| --- | --- |
| `sessions == 0`, completed invocation | No assembled TLS observed; inspect `tcp_streams` and `udp_443_frames`. |
| `sessions > 0`, `sessions_selected == 0` | Session selectors excluded assembled sessions. |
| `sessions_evicted` / `buffer_limit_hits` | Active state hit a resource ceiling; session statuses preserve domain evidence. |
| `sessions_omitted` / omission diagnostics | Aggregate output retention excluded results. |
| IP incomplete/eviction counters | Capture-global fragment evidence, independent of presentation filtering. |
| Terminal `error` / `io.output_record_limit` / `io.cancelled` or missing terminal | Output is incomplete; never infer success from a prefix. |

## Effective settings and resource ownership

`--resource-diagnostics` on JSON/NDJSON reports resolved settings (`value`,
`unit`, `stage`, `scope`, `enabled`, and `source`: `default`, `preset`,
`override`, `derived`, `fixed`); see
[stats](../examples/documents/output-stats-resources.json) and
[read](../examples/documents/output-read-resources.json). `--output-timeout-ms`
bounds each NDJSON write/flush wait (clipped by operation deadline; terminal
error cleanup gets a separate 1,000 ms allowance).

`Client::new` owns an isolated `Runtime` (`with_runtime` shares admission).
Netio `resources::native_snapshot` reports the aggregate 16-slot native root.
TCP connecting jobs and established sockets share 12 data places, reserving four
root places for eligible control work. A full root still refuses admission.
`tcp_connect_snapshot` reports that data allocation; `execution_snapshot` excludes
established sockets after their connect job ends, and `socket_snapshot` reports
established socket ownership. Socket transfer never acquires a second root slot.
Resident Linux namespace route services retain their root admission until they
actually exit; their cache holds at most four services, with idle retirement and
pressure eviction. Each service owns its namespace identity descriptor, closing
it before releasing its root admission; finished cache metadata owns no descriptor.
Idle executor threads are separate, bounded infrastructure and can still pin a
kernel namespace until their own retirement. The executor's thread ceiling
covers idle, busy, and retiring threads. A thread becomes reusable only after
outcome publication returns; retirement never joins on a new caller and waits
under its original control. This infrastructure ceiling can delay/refuse a new
job despite resource-root headroom. Capture cleanup and executor-thread retirement use independent bounded cleanup
services, each with at most 16 workers and a finite queue, so blocked cleanup in
one class does not consume the other's completion capacity. These services are
initialized only when needed. The maximum executor/capture-cleanup/retirement
worker allocations are 16/16/16, separate from facade Runtime workers. Native
resource snapshots do not count these resident infrastructure threads or arbitrary
provider-owned thread-local data.
`resources::executor_thread_snapshot` separately exposes retained executor slots
as busy, idle, and retiring; their sum stays at most 16 even when resource-grant
counts are zero. It conservatively includes completed handles awaiting pruning
by subsequent dispatch, and excludes the separate cleanup-service threads.
Hostname lookup has a nested four-job allocation plus native root admission;
`resolution::snapshot` includes unfinished cancelled lookups until they return.

A capture group requests stop from every source, then cooperative joins share
one independent one-second cleanup allowance. Unfinished native readers remain
charged through bounded reaper ownership. Legacy provider shutdown, interrupt,
statistics, and arbitrary synchronous callbacks cannot be forcibly preempted.

Analysis retains its exact effective run control through collector finalization
and trailing event delivery, including inherited reader deadlines. Built-in
finalizers check between records; custom `Collector::finish_controlled` can
cooperate internally. Mutable HTTP, TCP DNS, and fragment source accumulation
uses a charged ordered tree, freezing once into immutable published provenance.
The tree and complete flat result overlap in the charge during freezing;
retained snapshots keep their own shared leases. Logical charges are not RSS.

Trusted built-in live collectors use `Delivery::Cooperative` and execute in the
caller with control checks around publication. Arbitrary sinks and closures
retain `Delivery::Isolated` and acknowledged worker admission by default.
`Sink::publish_controlled` carries the effective operation control through
cooperative adapters and their nested waits; its default delegates to the
existing callback. This does not make arbitrary synchronous code preemptible.
`Runtime::new(0)` therefore permits cooperative collectors but refuses workers.
Isolated facade workers retain their runtime admission through actual thread
exit, callback captures, thread-local destructors, and opaque panic cleanup.
Cancellation stops waiting while `Runtime::snapshot()` keeps unfinished work
charged. Each runtime owns an independent cleanup allocation matching its worker
capacity, at most eight cleanup workers and eight queued joins in addition to
eight callback workers. Initialization failure releases admission and can be
retried; failed ownership transfers remain bounded and are retried without
releasing their charges. Snapshot counters count admission, not resident cleanup
threads. Running callbacks and destructors cannot be forcibly preempted.

CLI NDJSON emitters cooperate only when the encoder already isolates its writer;
text and direct writers retain isolated callbacks. Each line still waits for its
write and flush acknowledgement under the operation and invocation controls,
including cancellation when no invocation duration was supplied. Application NDJSON counts the exact compact
JSON bytes of `result` during its one serialization, excluding envelope metadata,
diagnostics, and newline as before. The independent 16 MiB record ceiling includes
the newline; refusal happens before writing a record. A writer failure can still
leave a partial record and prevents successful completion. Cancellation cannot
recall a record already handed to an arbitrary `Write`: a blocked write of a
`complete` record may finish later. The caller returns an error, the encoder
does not acknowledge completion, and the writer stays charged until actual
exit. Consumers must check the CLI exit status as well as the stream terminal.
Text and aggregate
application retention preserve their existing compact-JSON accounting traversal.
Default trace stages refresh caches while sharing the containing runtime;
an explicit `Trace.runtime` remains an independent root.

## Hosting untrusted captures with a hard stop

Run untrusted analyses in an OS-isolated process when a hard RSS or wall-clock
stop is required:

```sh
systemd-run --user --wait --pipe \
  -p MemoryMax=512M -p MemorySwapMax=0 -p TasksMax=32 -p RuntimeMaxSec=60s \
  -p KillMode=control-group -p KillSignal=SIGKILL \
  ./target/release/packetcraftr --output ndjson --resource-diagnostics \
  analyze tls CAPTURE.pcap --max-duration-ms 55000
```

See [resource presets](resource-presets.md) for named defaults and the
[verification contract](verification-contract.md) for forwarding accounting.

## Security investigations

`analyze hunt`, `dns-anomalies`, and `beacons` reuse capture, scope, reassembly,
provenance, and application limits. Security-specific `--max-groups` bounds
DNS windows, TCP beacon groups, and hunt source tables; `--max-observations`
bounds counted messages or retained connection attempts; `--max-findings` bounds
retained results. `--max-result-bytes` bounds serialized reports in every format.
These settings appear in resource diagnostics and have finite `ci-v1` and
`workstation-v1` presets. Exhaustion is an operational failure, not an empty
successful investigation. Group frame lists retain up to 64 representative
sources with explicit sampling metadata. See [security assessments](security-assessment.md).
