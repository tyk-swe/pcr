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
| Stats | CLI allocates only the selected table; `--top` caps final rows (busiest by frames then bytes/name, or earliest `io` buckets). |
| Results | JSON retains selected rows/sessions/chunks up to command limits; NDJSON holds one line per encoder (at most 16 MiB including newline). |
| Native/progress work | Live capture retains its bounded native queue; timed-out/cancelled workers retain permits until cleanup completes (`Runtime::snapshot()`). |

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
Netio `resources::native_snapshot` reports the shared 16-slot capture/route/TCP
pool; `tcp_connect_snapshot` reports nested connect admission.

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
