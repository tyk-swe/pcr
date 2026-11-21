# HTTP/3 exchange reconstruction

`packetcraftr analyze http3` reconstructs requests and responses from an offline QUIC v1 or v2 capture and a required NSS TLS key log. It accepts PCAP, PCAPNG, and redirected stdin with `-`, and detects gzip and Zstd compression automatically. The QUIC analyzer decrypts the capture and recovers stream bytes, while the HTTP/3 analyzer selects connections with negotiated `h3` ALPN and links each exchange to its QUIC connection and stream. Use [`analyze quic`](quic-analysis.md) for transport-level metrics, live capture, or raw stream export.

## Try the bundled capture

```sh
packetcraftr analyze http3 examples/captures/http3-demo.pcapng --keylog examples/captures/http3-demo.keys
```

The synthetic capture contains two requests on a QUIC v2 connection. Stream `0` carries a dynamic QPACK request header, a `103` informational response, a `200` final response with a `DATA` frame, and trailers. Stream `4` carries a static QPACK request and a `204` response.

From a source checkout, regenerate the synthetic capture and key log with `python3 scripts/generate_quic_fixtures.py`, which requires the Python `cryptography` package.

## Select and display exchanges

Pass `--connection ID` or `--stream ID` to narrow the report. Connection indices (`0`, `1`, ...) are capture-global QUIC indices assigned during analysis rather than wire connection IDs. `--stream ID` requires a client-initiated bidirectional QUIC stream ID (a multiple of 4 less than `2^62`, such as `0` or `4`). If `--connection` or `--stream` matches no HTTP/3 connection or stream, the command exits with a usage error.

Because `--filter EXPR` applies after IP reconstruction and before QUIC connection assembly, retain both peers' packets and include their control and QPACK streams when filtering so the decoder can recover transport and header compression state.

Header names, methods, and status codes are visible by default. Add `--include-header-values` to include header values such as paths, cookies, or authorization headers. In JSON and NDJSON output, UTF-8 values appear in `value` and non-UTF-8 values appear in `value_hex`, while non-UTF-8 header names appear as `[hex:...]` and text output escapes decoded values. `DATA` frames contribute `data_frames`, `data_bytes`, and `first_data_offset` totals, and their payload bodies are discarded from the report.

Text output is the default. Use `--output json` for an aggregate report, or `--output ndjson` for `http3_connection`, `http3_exchange`, and terminal `complete` records.

## Reading the evidence

### Completeness and frame references

Connection records carry physical capture frame references (`first_frame`, `last_frame`, `source_frames`, and `source_frames_omitted`) along with `scope` and `pending_packets`. Exchange records carry HTTP/3 frame offsets from the start of each QUIC stream direction. A stream side can retain complete headers and `DATA` frames observed before a gap, truncation, or reset.

Each request or response `side.complete` value describes whether that direction reconstructed cleanly without gaps, resets, omitted bytes, or HTTP/3 issues. The connection-level `transport_incomplete` flag allows normally open critical streams (control stream type `0`, QPACK encoder stream type `2`, and QPACK decoder stream type `3`) to stay open until the QUIC connection closes, while flagging unclosed or errored QUIC state, non-critical incomplete streams, or unaccepted 0-RTT streams. Terminal `summary.input_incomplete` describes capture-wide loss such as truncated frames or incomplete IP sources, alongside summary counters for `unknown_alpn`, `skipped_alpn`, `quic_limit_hits`, `quic_evictions`, `quic_unassociated_packets`, and `keylog_records_rejected`.

### Message and critical stream checks

The analyzer flags any observed FIN or reset on a control or QPACK stream (`closed_control_stream`, `closed_qpack_encoder_stream`, `closed_qpack_decoder_stream`), duplicate critical streams (`duplicate_critical_stream`), missing control or settings frames (`missing_control_stream`, `missing_settings`), and invalid settings (`invalid_settings`).

On exchange streams, the analyzer checks request targets and pseudo-headers, frame placement, and declared `Content-Length` values when the capture contains the complete stream (`content_length_mismatch`). A clean stream end without initial headers produces `missing_initial_headers`, and a clean stream end after an informational response produces `missing_final_response`. The analyzer also flags nonempty `DATA` on a `204`, `205`, `304`, or known `HEAD` response (`unexpected_response_content`), trailers on a `204` or `304` (`invalid_frame_placement`), and extra `HEADERS` or server `PUSH_PROMISE` frames in either direction after a successful `CONNECT` response (`invalid_frame_placement`). An Extended `CONNECT` request stays incomplete if captured server `SETTINGS` disable `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`extended_connect_disabled`) or if the setting cannot be verified (`extended_connect_settings_unavailable`).

### QPACK replay and 0-RTT handling

The analyzer replays each endpoint's observed QPACK encoder stream under the opposite endpoint's advertised `SETTINGS_QPACK_MAX_TABLE_CAPACITY`. A `required_insert_count` of `0` indicates static or literal decoding, and a positive count records the unique interpretation that fits the observed insertion and eviction history. Because decoder acknowledgment timing is outside passive capture analysis, this count describes the capture evidence. If multiple wrapped counts fit, the analyzer reports `qpack_ambiguous`. When required dynamic state is missing or unverified, the analyzer reports `qpack_unavailable` and continues with independent static or literal sections. Rejected or unresolved 0-RTT bytes are excluded from HTTP/3 inspection, while accepted 0-RTT bytes are merged into ordinary QUIC streams before HTTP/3 parsing.

## Resource limits and supported traffic

| Limit | Default | CLI flag or internal bound | What it bounds |
| :--- | :--- | :--- | :--- |
| QPACK history | 4 MiB | Internal `max_qpack_history_bytes` | Replayed QPACK dynamic table history per sender |
| Header section | 64 KiB | Internal `max_header_section_bytes` | Decoded size of one HTTP/3 header section |
| Exchange evidence | 256 KiB | Internal `max_exchange_bytes` | Retained decoded header budget across one exchange |
| Parser work | 1,000,000 steps | Internal `max_steps` | Parser work units per QUIC connection |
| Issues per side | 64 | Internal `MAX_ISSUES` | Retained issues per request or response side (`issues_omitted` counts excess) |
| QUIC stream bytes | 1 MiB | `--max-quic-stream-bytes` | Retained bytes per QUIC stream direction (within QUIC's 64 MiB default state budget) |
| Application output | 64 MiB | `--max-application-output-bytes` | Rendered connection and exchange evidence in the selected format (`1` byte to 256 MiB) |
| Key-log input | 64 MiB / 16 MiB | Internal CLI and core bounds | Required regular key-log file (64 MiB read cap, up to 65,536 records and 16 MiB in memory) |

Use `--max-quic-stream-bytes` for larger exchanges, subject to the QUIC collector's default 64 MiB state budget, 8,192 active connections, 4,096 stream directions per connection, and 120-second idle expiry. Key logs must be regular files (pipes, devices, and directories are rejected). Server push streams, tunnel payload decoding inside `CONNECT` `DATA` frames, and live capture (`--interface`) are outside this command's scope. Run `packetcraftr analyze http3 --help` for shared offline input bounds.

## References

HTTP/3 framing and critical streams follow [RFC 9114](https://www.rfc-editor.org/rfc/rfc9114). Header semantics follow [RFC 9110](https://www.rfc-editor.org/rfc/rfc9110), Extended `CONNECT` follows [RFC 9220](https://www.rfc-editor.org/rfc/rfc9220), and QPACK header compression follows [RFC 9204](https://www.rfc-editor.org/rfc/rfc9204).
