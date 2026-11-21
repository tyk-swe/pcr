# QUIC transport analysis

`packetcraftr analyze quic` analyzes QUIC v1 and v2 traffic from PCAP, PCAPNG, redirected stdin with `-`, or native live capture. Offline inputs detect gzip and Zstd compression automatically. The analyzer authenticates and decrypts Initial packets without endpoint secrets, and it uses NSS-format TLS key logs to decrypt Handshake, 0-RTT, and 1-RTT traffic with AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305. Use [`analyze http3`](http3-analysis.md) to reconstruct HTTP/3 exchanges from an offline capture and key log.

## Try the bundled capture

```sh
packetcraftr analyze quic examples/captures/quic-demo-v2.pcapng --keylog examples/captures/quic-demo.keys --include-data
```

In this synthetic capture, client stream `0` carries `hello world`, server stream `0` carries `received hello world` followed by a newline, and client stream `4` carries `updated keys` followed by a newline. The capture exercises packet coalescing, reordered STREAM data, a migrated path, a validated challenge response, and a key update. Its synthetic handshake demonstrates passive decoding and does not establish a valid TLS session with a real endpoint.

The `examples/captures/` directory ships synthetic QUIC fixtures and key logs. `quic-demo-v1.pcap` and `quic-demo-v2.pcapng` pair with `quic-demo.keys` for QUIC v1 and v2 transport flows. `quic-demo-truncated.pcap` and `quic-demo-incomplete-ip.pcap` retain complete stream bytes while exposing capture loss, including loss discovered after a connection retires. `quic-demo-early-data.pcap` and `quic-demo-early-data.keys` separate rejected 0-RTT bytes from their 1-RTT replacement. From a source checkout, regenerate all synthetic QUIC and HTTP/3 fixtures with `python3 scripts/generate_quic_fixtures.py`, which requires the Python `cryptography` package.

## Analyze a file or live capture

```sh
packetcraftr analyze quic capture.pcapng --keylog session.keys
packetcraftr --output ndjson analyze quic --interface eth0 --keylog session.keys
packetcraftr --output json analyze quic capture.pcapng --keylog session.keys --connection 0 --stream 0 --direction client --include-data
```

### Inputs and filtering

File input and `--interface` are mutually exclusive, and `--interface` may be repeated up to 256 times. Offline builds work without `libpcap`. Live capture uses the shared native capture workflow, feature requirements, permissions, queue bounds (`--max-queue-frames`, `--max-captured-bytes`, `--snap-length`, `--overflow-policy`), `--timeout-ms`, cancellation, and cleanup.

Both `--capture-filter` and `--promiscuous` require `--interface`. `--capture-filter` applies a numeric BPF expression before capture queue admission and rejects symbolic names. `--filter` applies a display filter after IP reconstruction and before QUIC connection assembly, so any display filter should retain handshake packets and migrated paths for the connections you want to inspect.

The `--connection`, `--stream`, and `--direction` (`both` by default, `client`, or `server`) selectors apply after connection assembly, preserving handshake context and key state. If `--connection` or `--stream` matches no connection or stream, the command exits with a usage error.

### Key logs and live updates

Key logs are optional and must be regular files. Pipes, devices, and directories are rejected before capture starts, and the CLI rejects key-log inputs larger than 64 MiB. When an endpoint supports `SSLKEYLOGFILE`, the analyzer reads secrets locally and never includes secret values in reports. When secrets are absent, Initial packets still yield visible handshake metadata such as SNI, offered ALPN, cipher suite, client transport parameters, and JA3 and JA4 QUIC fingerprints. Encrypted ClientHello (ECH) outer SNI values are flagged with `sni_is_outer`.

During live capture, the analyzer follows appended records on the opened key-log file and retries retained encrypted packets whenever new secrets arrive. Partial trailing lines wait for more bytes, and the final poll at the end of capture accepts a final line without a newline. Replacing or rotating the key-log file requires restarting analysis. Because key logs and pending packets have finite limits, secrets arriving after rejection or eviction cannot recover discarded traffic.

## Read the report

### Output formats and payloads

Text, JSON, and NDJSON output show connection and stream metadata by default. Pass `--include-data` to include hexadecimal stream payloads, which adds `data_hex` to JSON stream ranges, emits `stream_data` events in 64 KiB chunks for NDJSON, and writes `data` lines in 64 KiB chunks for text output.

In NDJSON mode, the analyzer emits `connection` events (preceded by `stream_data` events when `--include-data` is set) as each connection retires or when analysis ends, followed by a terminal `complete` event. Connection records track physical capture `source_frames` (up to 4,096 frames, counting excess frames in `source_frames_omitted`) along with capture interface and tunnel `scope`, including across IP fragment reassembly.

### Observed handshake and transport metrics

Reports expose observed TLS messages, client and server transport parameters (up to 256 entries per side), connection IDs, migration paths, path challenge validations, key updates, DATAGRAM counts and byte totals, flow-control blocking frames, closes, stateless resets, stream overlap conflicts, final-size errors, and pending packet counts.

Handshake fields such as `client_finished_frame`, `server_finished_frame`, and `handshake_done_frame` record passive packet observations only. The analyzer does not verify certificates, Finished MACs, or the TLS transcript. Metrics such as `ack_samples` and `min_ack_elapsed_ms` reflect passive capture timestamps and include observer placement and delayed acknowledgement effects, and `observed_packet_gaps` counts packet-number skips without proving network packet loss.

### Completeness and capture loss

In a streaming run, `summary.input_incomplete` applies to every connection in the run, including `connection` records emitted before capture loss became known. Aggregate JSON reports and `--write` export manifests mark all retained connections `incomplete` before publication when capture-wide loss occurs. On individual streams, `stream.complete` describes recovered contiguous byte coverage up to `final_size` without resets or stream errors, so it can remain `true` even when `connection.incomplete` or `summary.input_incomplete` is `true`.

### Protocol scope and explicit diagnostics

Separate packet-number spaces (Initial, Handshake, and Application) and absolute stream byte offsets handle reordered packets and retransmissions. Short-header 1-RTT packets require previously observed connection ID context from long headers, `NEW_CONNECTION_ID` frames, or server `preferred_address` transport parameters. Ambiguous association, unsupported versions or frames, missing secrets or handshake context, authentication failures, truncation, resource eviction, and incomplete capture evidence remain explicit in summary counters, diagnostics, and `end_reason`.

Spin-bit RTT estimation, application-level DATAGRAM payload interpretation, multipath QUIC extensions, and compatible version negotiation that changes the QUIC version within one connection are outside this release. A different observed long-header version on an existing connection records an `unsupported_version_transition` diagnostic and does not advance decryption state.

## Export reconstructed streams

Create the destination directory first, then pass it to `--write`.

```sh
mkdir streams
packetcraftr analyze quic capture.pcapng --keylog session.keys --connection 0 --write streams
```

Each contiguous stream range becomes a raw binary file named `quic-CONNECTION-STREAM-SENDER-accepted-OFFSET.bin`, where `SENDER` is `client` or `server`. Rejected or unresolved 0-RTT ranges use `early` in place of `accepted`, while `accepted` covers ordinary 1-RTT data and accepted 0-RTT data merged into ordinary stream offsets. A single export writes at most 4,096 range files.

`quic-manifest.json` follows `schemas/packetcraftr.quic-streams.v1.schema.json`. It records absolute offsets, gaps, final sizes, reset errors, completeness, early-data acceptance, and filenames without inventing bytes for missing ranges.

All exported files are staged and synced before publication and never overwrite existing paths. An existing `quic-manifest.json` fails before reading input, an existing range file fails before publication, and if publication fails mid-batch after publishing some files, the error names the files that remain. On Unix, `--write` binds the destination directory before reading capture input so all stream ranges and the manifest use that same directory handle even if the path is renamed or replaced. On Windows, the shared staged-output limits apply, where the destination directory cannot be renamed or deleted while held open, while ancestor retargeting and staging-name substitution during rename are not prevented and have not been verified natively.

The `--max-application-output-bytes` flag (default 64 MiB, non-zero) caps inspected payloads, JSON connection retention, exported range bytes, and the `quic-manifest.json` manifest. The `--max-output-connections` flag (default 256, non-zero) caps retained connections in aggregate JSON reports (omitting additional connections in `summary.connections_omitted` when not exporting) and sets the maximum connection count allowed in `--write` exports.

## Resource limits

| Limit | Default | CLI flag or internal bound | What it bounds |
| :--- | :--- | :--- | :--- |
| Active connections | 8,192 | `--max-connections` | Concurrent tracked QUIC connections |
| Charged QUIC state | 64 MiB | `--max-quic-buffered-bytes` | Aggregate connection, reset-queue, and key-log state |
| Per-stream bytes | 1 MiB | `--max-quic-stream-bytes` | Retained bytes per stream direction (separate for unaccepted 0-RTT) |
| Pending packets | 64 | `--max-pending-packets` | Deferred encrypted packets per connection, and capture-wide stateless reset candidates |
| Stream directions | 4,096 | `--max-quic-streams` | Tracked stream entries per connection |
| Idle expiry | 120,000 ms (120 s) | `--quic-idle-expiry-ms` | Capture-time inactivity threshold before retirement |
| Output connections | 256 | `--max-output-connections` | Aggregate JSON and `--write` manifest connection limit |
| Application output | 64 MiB | `--max-application-output-bytes` | Inspected payloads, JSON connections, and `--write` export bytes |
| Ranges and frame lists | 4,096 | Internal `max_ranges` | Disjoint ranges per stream, frames per packet, coalesced packets per datagram, tracked packet numbers, and `source_frames` per connection |
| Connection IDs and paths | 64 | Internal `max_connection_ids` | Connection IDs, paths, retired sequences, and pending path challenges per connection |
| Diagnostics | 64 | Internal `max_diagnostics` | Retained diagnostics per connection |
| Key-log input | 64 MiB / 16 MiB | Internal CLI and core bounds | 64 MiB file read cap, plus up to 65,536 records and one quarter of `--max-quic-buffered-bytes` (capped at 16 MiB) in memory, max 512 bytes per line |
| Exported range files | 4,096 | Internal exporter limit | Maximum raw range files created by one `--write` run |

When the active connection or charged byte limit is reached, the least-recently observed connection retires with `end_reason` set to `connection_limit` or `buffer_limit` and records a matching diagnostic that marks the connection incomplete. Idle connections retire after `--quic-idle-expiry-ms` of capture time with `end_reason` set to `idle_expiry`. These bounds describe retained analysis state rather than total process RSS. Run `packetcraftr analyze quic --help` for all transport, live capture, and shared offline input bounds.

Unassociated short-header packets of at least 21 bytes are retained as possible stateless resets until their tokens become available from `NEW_CONNECTION_ID` frames or server transport parameters. That candidate queue shares `--max-quic-buffered-bytes`, uses `--max-pending-packets` as its capture-wide entry ceiling, expires entries after `--quic-idle-expiry-ms` of capture time, and drops older candidates while incrementing `buffer_limit_hits` when full.

## References

Packet protection and key schedules follow [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001), [RFC 9369](https://www.rfc-editor.org/rfc/rfc9369) (QUIC v2), and the [NSS key-log format](https://nss-crypto.org/reference/security/nss/legacy/key_log_format/index.html). Transport interpretation, recovery semantics, and datagram framing follow [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002), and [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221).
