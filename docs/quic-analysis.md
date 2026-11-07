# QUIC transport analysis

`packetcraftr analyze quic` analyzes QUIC v1 and v2 from PCAP, PCAPNG, stdin, or native live capture. It authenticates and decrypts Initial packets without endpoint secrets. NSS-format TLS key logs enable Handshake, 0-RTT, and 1-RTT decryption with AES-128-GCM, AES-256-GCM, or ChaCha20-Poly1305. HTTP/3 and QPACK decoding are outside this engine.

```sh
packetcraftr analyze quic capture.pcapng --keylog session.keys
packetcraftr --output ndjson analyze quic --interface eth0 --keylog session.keys
packetcraftr --output json analyze quic capture.pcapng --keylog session.keys --connection 0 --stream 0 --direction client --include-data
```

Key logs must be regular files. Pipes, devices and directories are rejected before capture starts. Use an endpoint that supports TLS key logging. `SSLKEYLOGFILE` support depends on the endpoint and its build. Key logs contain sensitive session secrets. The analyzer reads secrets locally and never includes them in reports. Missing secrets still permit Initial handshake metadata, including visible SNI, offered ALPN, and QUIC fingerprints. ECH outer names are identified as outer names.

File and live inputs are mutually exclusive. Offline builds work without libpcap. Live input uses the existing native capture workflow, feature requirements, permissions, queue bounds, cancellation, and cleanup. `--capture-filter` applies numeric BPF before queue admission. `--filter` applies after IP reconstruction. Connection, stream, and direction selectors apply after connection assembly, preserving handshake context.

Live capture follows appended secrets on the opened key-log file and retries retained encrypted packets. Partial trailing lines wait for more bytes. Replacing or rotating the key-log file requires restarting analysis. The final poll accepts a final line without a newline. Key logs and pending packets have finite limits, so secrets arriving after eviction cannot recover discarded traffic.

Text, JSON, and NDJSON show metadata by default. `--include-data` explicitly includes hexadecimal payloads. NDJSON uses `stream_data`, `connection`, and `complete` events. Connection and stream results are emitted when their connection is retired or analysis ends. The report tracks original physical source frames and their capture interface and tunnel scope, including IP reconstruction.

## Export reconstructed streams

Create the destination directory first, then export selected streams.

```sh
mkdir streams
packetcraftr analyze quic capture.pcapng --keylog session.keys --connection 0 --write streams
```

Each contiguous range becomes a raw file named `quic-CONNECTION-STREAM-SENDER-accepted-OFFSET.bin`. Rejected or unresolved 0-RTT uses `early` in place of `accepted`. The name `accepted` also covers ordinary 1-RTT data. `quic-manifest.json` records absolute offsets, gaps, final sizes, reset errors, completeness, early-data acceptance, and filenames. Its contract is `schemas/packetcraftr.quic-streams.v1.schema.json`. No bytes are invented for missing ranges. Accepted 0-RTT merges into ordinary stream offsets. Rejected or unresolved early bytes remain separate.

Files are staged and synced before publication and never overwrite existing paths. If publication fails after some files are published, the error identifies the files that remain. An existing manifest or range file makes the operation fail. The default payload allowance is 64 MiB across inspected or exported data, controlled by `--max-application-output-bytes`. JSON metadata and the export manifest also consume that output allowance. `--max-output-connections` bounds JSON retention and export manifest connections.

## Interpretation and bounds

Reports expose observed TLS messages, transport parameters, connection IDs, migration paths, path challenge responses, key updates, DATAGRAM counts, blocking, closes, resets, stream overlap conflicts, final-size errors, and pending packets. Finished and HANDSHAKE_DONE fields record observations. They do not verify certificates, Finished MACs, or the TLS transcript. ACK elapsed samples are passive observations and include capture position and delayed acknowledgement effects. Packet-number gaps alone do not prove network loss.

The final summary’s `input_incomplete` applies to every connection in a streaming run, including records emitted before capture loss became known. Aggregate reports and export manifests mark those connections incomplete before publication. Stream `complete` describes recovered byte coverage and can remain true when the capture itself is incomplete.

Separate packet-number spaces and absolute stream offsets handle reordered packets and retransmitted ranges. Short headers require observed connection ID context. Ambiguous association, unsupported versions or frames, missing secrets, authentication failures, truncation, resource eviction, and incomplete capture evidence remain explicit. Spin-bit RTT estimation, application-level DATAGRAM interpretation, multipath QUIC extensions, and compatible version negotiation that changes the version within one connection are outside this release. A different observed long-header version is reported explicitly and does not advance decryption state.

Defaults allow 8,192 active connections, 64 MiB charged QUIC state, 1 MiB per stream direction, 64 pending encrypted packets per connection, 4,096 stream directions per connection, 4,096 retained ranges, 64 connection IDs, 64 diagnostics, and 120 seconds of capture-time idle expiry. Least-recently observed connections retire under pressure with an incompleteness reason. These bounds describe retained analysis state, not total process RSS. Use `analyze quic --help` for controls and shared input bounds.

## Reproducible demo

`examples/captures/quic-demo-v1.pcap` and `quic-demo-v2.pcapng` contain only synthetic traffic. Their matching `quic-demo.keys` contains synthetic secrets. The `quic-demo-truncated.pcap` and `quic-demo-incomplete-ip.pcap` fixtures retain complete stream bytes while exposing capture loss, including loss discovered after a connection retires. The `quic-demo-early-data.pcap` fixture and matching `.keys` distinguish rejected early bytes from their application-data replacement. Regenerate them with `python3 scripts/generate_quic_fixtures.py`, which requires the Python cryptography package.

```sh
packetcraftr analyze quic examples/captures/quic-demo-v2.pcapng --keylog examples/captures/quic-demo.keys --include-data
```

The client stream 0 contains `hello world`, the server stream 0 contains `received hello world` followed by a newline, and client stream 4 contains `updated keys` followed by a newline. The capture includes coalescing, reordered STREAM data, a migrated path, a validated challenge response, and a key update. Its synthetic handshake demonstrates passive decoding and does not establish a valid TLS session with a real endpoint.

Packet protection follows [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001), [QUIC v2](https://www.rfc-editor.org/rfc/rfc9369), and the [NSS key-log format](https://nss-crypto.org/reference/security/nss/legacy/key_log_format/index.html). Transport interpretation follows [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000), [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002), and [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221).
