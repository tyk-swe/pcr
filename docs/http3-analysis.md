# HTTP/3 exchange reconstruction

`packetcraftr analyze http3` reconstructs requests and responses from an offline QUIC v1 or v2 capture and an NSS TLS key log. It accepts PCAP, PCAPNG, and redirected stdin with `-`. The QUIC analyzer decrypts the capture and recovers stream bytes. The HTTP/3 analyzer selects connections with negotiated `h3` and links each exchange to its QUIC connection and stream.

```sh
packetcraftr analyze http3 examples/captures/http3-demo.pcapng --keylog examples/captures/http3-demo.keys
```

The synthetic example contains two requests. Stream 0 has a dynamic QPACK request header, a 103 informational response, a 200 final response, and trailers. Stream 4 has a 204 response. Add `--connection ID` or `--stream ID` to narrow the report. QUIC connection IDs in the report are capture-local indices. Retain both peers' traffic and include their control and QPACK streams when filtering so the decoder can recover the required state.

Header names, methods, and status codes are visible by default. Add `--include-header-values` to include values such as paths, cookies, or authorization headers. JSON uses `value_hex` for non-UTF-8 values. Text output escapes decoded values. DATA frames contribute counts and byte totals, and their bodies are discarded from the report.

## Reading the evidence

Connection records carry physical capture frame references. Exchange records carry HTTP/3 frame offsets within each direction of the QUIC stream. A side can contain complete headers and DATA frames before a truncation or reset. Its `complete` value describes reconstruction of that direction, and the terminal `input_incomplete` flag describes capture-wide loss. The analyzer checks request targets, frame placement, and declared body lengths when the capture contains the complete message. The connection-level `transport_incomplete` flag allows control and QPACK streams to stay open until the QUIC connection closes. An observed control or QPACK stream FIN or reset produces a diagnostic. The analyzer also flags duplicate critical streams.

A clean stream end after an informational response produces `missing_final_response`. The analyzer flags nonempty DATA on a 204, 205, 304, or known HEAD response, trailers on a 204 or 304, and extra HEADERS in either direction of a successful CONNECT. An Extended CONNECT request stays incomplete if the captured server SETTINGS disable the protocol or the setting cannot be verified.

The analyzer replays each endpoint's observed QPACK encoder stream under the opposite endpoint's advertised capacity. A positive `required_insert_count` records the unique interpretation that fits the observed insertion and eviction history. Decoder acknowledgment timing is outside the analysis, so this count describes the capture evidence. If multiple wrapped counts fit, the analyzer reports `qpack_ambiguous`. When required state is missing, the report marks it unavailable and continues with independent static or literal sections. Rejected or unresolved 0-RTT bytes are excluded.

Use `--output json` for the aggregate report or `--output ndjson` for `http3_connection`, `http3_exchange`, and terminal `complete` records. The default parser limits reserve 4 MiB of QPACK history per sender, 64 KiB per header section, 256 KiB of retained evidence per exchange, and one million units of parser work per connection. QUIC retains 1 MiB per stream direction by default. Use `--max-quic-stream-bytes` for larger exchanges, subject to the QUIC collector’s shared state budget. Use `--max-application-output-bytes` to bound published evidence. Push streams, tunnel payload decoding, and live capture are outside this command's scope.

Regenerate the synthetic capture and key log with `python3 scripts/generate_quic_fixtures.py`. The generator uses Python's `cryptography` package.
