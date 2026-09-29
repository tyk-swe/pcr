# Practical offline tools

The portable `packetcraftr_core` APIs add ten offline capabilities, available through the corresponding CLI commands.

| Feature | Rust API | CLI |
| --- | --- | --- |
| WebSocket following | `analysis::websocket::Collector` | `websocket PATH --stream tcp:N` |
| TLS server certificates | `analysis::tls::Collector::with_certificates` | `tls PATH --certificates` |
| TCP handshake and ACK timing | `analysis::stats::Table::TcpTiming` | `stats PATH --table tcp-timing` |
| Captured-length histogram | `analysis::stats::Table::Sizes` | `stats PATH --table sizes` |
| HTTP entity export | `analysis::http::Collector::with_body_chunks` | `http PATH --write DIR` |
| HTTP content decoding | `analysis::http::decode_content` | `http PATH --write DIR --decode-content` |
| Capture deduplication | `capture_file::dedup` | `dedup PATH --write FILE` |
| Capture splitting | `capture_file::split` | `split PATH --write DIR` |
| Exact capture timestamp shift | `capture_file::shift_time`, `TimeShift` | `shift-time PATH --seconds SIGNED_DECIMAL --write FILE` |
| CIDR address mapping | `transform::CidrMap`, `rewrite_with_cidr_maps` | `rewrite PATH --source-cidr-map OLD=NEW --write FILE` |

WebSocket collection uses reassembled TCP deliveries, requires both HTTP upgrade directions or explicit decode-as, unmasks frames, assembles continuations, and emits control frames. Text messages require valid UTF-8. RSV bits are rejected, including negotiated compression that cannot be decoded faithfully. Messages are bounded to 16 MiB and the two direction buffers share a 32 MiB ceiling. Missing continuation bytes remain explicit diagnostics.

The WebSocket CLI also applies the shared application buffer limit (16 MiB by
default); the smaller of it and `--max-websocket-buffer-bytes` governs both
directions and partial messages. `--max-application-messages` counts data
messages and control frames together (4,096 by default). Retained and emitted
evidence has a cumulative byte charge for event metadata and payloads, bounded
by `--max-application-retained-bytes` (64 MiB by default); serialized output has
its own `--max-application-output-bytes` limit. Resource presets apply to each
of these shared limits. Stream-count and source-span arguments are unavailable
because the command selects one conversation and does not retain source spans.

TLS certificate collection is optional so existing hello-only collection remains unchanged. Plaintext TLS 1.2 and earlier chains retain every exact DER byte and its SHA-256 digest, within 32 certificates and the existing handshake buffer ceiling. TLS 1.3 reports encrypted collection status. Certificate collection status is separate from the hello handshake status; missing chains remain incomplete, never invented.

TCP timing reports SYN-to-SYN/ACK and SYN-to-final-ACK duration, plus ACK RTT count, minimum, mean, and maximum for each canonical direction. Retransmitted sequence ranges are excluded using Karn's rule; clock regressions, outstanding segments without captured ACKs, and pending-table exhaustion have separate counters. Sequence comparisons handle 32-bit wrap within the TCP serial-number half-space. At most 4,096 outstanding observations are retained per direction.

Nonoverlapping reordered segments remain valid RTT observations. Each direction
also retains up to 4,096 previously observed ranges to detect overlaps after an
ACK; older arrivals whose history was discarded are excluded under the limit
counter. A fresh SYN after tuple reuse clears outstanding ranges and handshake
state. Outstanding ranges from the old connection count as missing ACKs, and
RTT statistics accumulate across the conversation. Handshake durations describe
the most recently observed connection.

Size bins count captured lengths, including truncated captures, at 0–63, 64–127, 128–255, 256–511, 512–1023, 1024–1518, 1519–4095, and 4096+ bytes. Empty bins remain present in the histogram.

HTTP body chunks contain entity bytes after transfer framing, so chunk sizes, CRLFs, and trailers never appear in exported content. A terminal message event follows the chunks. Callers stage entity data until the message reports complete, discard incomplete objects, and publish deterministic files atomically. Content decoding streams gzip or zlib-wrapped deflate under a separate decoded-byte ceiling, normally 16 MiB and configurable up to the existing 256 MiB body ceiling, retaining encoded entity files. The collector enforces 256 MiB of cumulative emitted entity bytes; filesystem callers also bound cumulative encoded and decoded output bytes.

Deduplication compares exact packet bytes, original lengths, link type, normalized capture interface, and capture direction against preceding input frames, independently of timestamps. The default window includes 1,024 preceding input frames and retains at most 64 MiB of packet bytes and per-frame metadata. Retained-byte exhaustion is an explicit failure. Packet and metadata records remain raw, preserving unknown options and bytes.

Split selectors are packet count, captured byte count, or duration; only one selector is accepted. Packets remain indivisible, so an individual packet may exceed a requested byte threshold. Each output contains the source capture header and all required interface declarations for its initial section. Raw section headers have their section-length declaration cleared because selection changes their lengths. At most 64 outputs may be requested; retained source header/interface declarations are bounded to 64 MiB. Filesystem callers must stage the complete set and refuse overwrites before publishing.

Timestamp shifts parse exact signed decimal seconds and translate the value into source-interface ticks. Sub-tick shifts and raw timestamp overflow are rejected. Classic packet timestamps, PCAPNG Enhanced/Obsolete packet timestamps, Interface Statistics timestamps, and known start/end statistics timestamp options shift together. Simple Packet Blocks remain timestamp-less. Every other source byte remains unchanged.

CIDR maps require equal address families and equal prefix widths, canonical network bases, at most 64 maps total, and nonoverlapping source ranges within each direction. Unmatched addresses and non-IP frames retain their original bytes; mapped addresses preserve host bits. Fixed address overrides take precedence. The existing rewrite path repairs all supported checksums and retains capture identity while preserving its existing refusal of incomplete datagrams or unrepairable checksum coverage.
