# PacketcraftR

PacketcraftR is a Rust library and CLI for protocol development,
interoperability testing, and authorized network diagnostics. It provides
exact packet construction, bounded dissection, capture-file I/O, offline
analysis, and policy-gated live networking.

Current release: pre-1.0 beta `0.5.0-beta.3`. Rust APIs and versioned serialized
contracts may change between beta releases; review the [changelog](CHANGELOG.md)
and [beta.3 migration note](docs/migration-beta.3.md) before upgrading.

> **Authorized use:** PacketcraftR is designed for controlled labs, protocol
> testing, and diagnostics on systems and networks you own or are explicitly
> authorized to test. Its opt-in flags are technical controls, not permission.

## Quick Start

These offline examples work in every feature profile:

```console
packetcraftr protocols
packetcraftr --output hex build --packet 'raw(text=hello)'
packetcraftr --output json dissect --link-type 228 \
  --hex '450000210000000040118e95c0000201c633640230390009000d9f8868656c6c6f'
packetcraftr --output ndjson read examples/captures/tls-handshake.pcapng \
  --max-frames 100
packetcraftr tls examples/captures/tls-handshake.pcapng
packetcraftr --output json build \
  --packet-file examples/documents/packet-ipv4-udp.json
```

The `tls` example assembles ClientHello and ServerHello records across TCP
segments and reports SNI, negotiated parameters, JA3/JA3S/JA4, and status.
Use `packetcraftr --help`, `packetcraftr <COMMAND> --help`, and
`packetcraftr protocols [PROTOCOL]` for the authoritative command, option, and
protocol catalogs.

Recipe commands also accept a packet expression, JSON, or YAML from redirected
stdin when neither `--packet` nor `--packet-file` is supplied. YAML comments and
mapping key order work the same as in `.yaml` files. For example,
`packetcraftr --output hex build < examples/documents/packet-ipv4-udp.json` builds the
document under the same input byte and build limits. Terminal stdin is rejected
instead of waiting for interactive input.

Offline `read`, `expert`, `follow`, `stats`, and `tls` accept `-` as the capture
path to stream PCAP or PCAPNG from redirected stdin. For example,
`packetcraftr --output ndjson read - < examples/captures/tls-handshake.pcapng`.
The same frame, byte, interface, and analysis limits apply to files and pipes.
Terminal stdin is rejected; live `replay` remains file-based. Reads are
synchronous and can block between duration checks while waiting for more input;
a duration limit does not interrupt a pending stdin read.

Capture output from `read` preserves source records and requires the same format
by default. To export matching physical frames from either capture format, use
`packetcraftr --output pcapng read capture.pcap --normalize --filter 'udp' > selected.pcapng`.
Normalization writes one new section with remapped selected interfaces, retaining
packet bytes, captured/original lengths, link types, direction, and interface
snapshot length, timestamp resolution, and offset. It discards comments, unknown
blocks/options, and original section structure; it does not reassemble packets.
Timestamps must be exactly representable as nanosecond capture time and at their
interface resolution. Unrepresentable times and selected frames without timestamps
fail instead of receiving invented times.
Zero matches produce a valid section with no interfaces or packets. Input limits
count filtered-out frames too; the same block and interface ceilings bound output.

| Area | Commands |
| --- | --- |
| Packets and captures | `build`, `dissect`, `protocols`, `read` |
| Offline analysis | `expert`, `follow`, `stats`, `tls`, `fuzz` |
| Native inspection and planning | `interfaces`, `routes`, `plan` |
| Live workflows | `send`, `exchange`, `capture`, `replay`, `scan`, `traceroute`, `dns`, `fuzz --live` |

## Packet sets and decode-as

`build`, `exchange`, and `send` accept repeatable axes over zero-based layer
fields:

```console
packetcraftr --output ndjson build --packet 'ipv4(dst=192.0.2.1)/udp()' --axis '0.ttl=[1,64]' --axis '1.dport=[9000,9001]'
```

This produces four packets in Cartesian order, with the last axis varying
fastest. `--max-template-packets` defaults to 10,000 and is checked before
preparation. Axes use expression values, reject empty lists and repeated fields
(including aliases), and share a 1 MiB input ceiling. An unsigned range operand
such as `0.ttl=1..64` or `0.ttl=1..64:8` expands its inclusive `START..END`
span with an optional step; endpoints may be decimal or `0x` hexadecimal.
Reversed ranges, zero steps, and ranges that exceed the packet ceiling fail
before any packet is built. Build streams text, one hex line per packet, or
NDJSON `packet` events followed by `complete`; JSON and
raw require one packet. Exchange applies one budget and response window to the
whole set, checking every packet's endpoints and final bytes.

`send --repeat N` replays the complete expansion `N` times in expansion order
and `--rate N` bounds transmission starts to `N` packets per second. The
first frame leaves immediately; a fixed interval paces later sends. The
expansion times repetition is checked arithmetic against one packet/byte
budget — there is no unbounded repeat — and a scheduled delay past the
operation ceiling fails before anything transmits. Every frame is planned,
endpoint-checked, and final-wire authorized in turn; text, hex, and raw emit
each confirmed frame as it lands, and a later failure, cancellation, or
exhausted budget stops the run without discarding earlier evidence. Aggregate JSON reports `frames` (each
with its one-based `pass` and expansion `index`) and `passes_completed`; PCAP
and PCAPNG capture every transmitted frame.

Offline `dissect`, `read`, `follow`, `stats`, `expert`, and `tls` accept
`--decode-as 'udp.port=5353:dns'`. TCP ports support `tls` and `raw`; UDP ports
support `dhcpv4`, `dhcpv6`, `dns`, `ntp`, `vxlan`, `geneve`, and `raw`. A
mapping overrides the built-in
binding for that port; transport source/destination precedence stays unchanged.
Conflicting declarations are rejected. `--tls-port 4433` is shorthand for
`--decode-as 'tcp.port=4433:tls'`. At most 256 declarations and 64 KiB of mapping
text are accepted. Decoding and display filters use the same configured registry.

## Filtered capture export

Save a focused capture in the source format:

```console
packetcraftr --output pcapng read capture.pcapng \
  --filter 'udp.port == 53' > dns.pcapng
```

Selected packet records retain their original bytes, timestamps, and options.
All metadata is retained; PCAPNG section lengths become unknown and interface
statistics still describe the source capture. Filters use original frame numbers
and do not automatically include related packets or fragments. Stream selectors
are unsupported; format conversion requires `--normalize --output pcapng`. All
input packets count toward the finite frame/byte limits, and an empty selection
is valid. Errors can leave partial output. Without `--filter` or `--normalize`,
capture output remains a byte-for-byte rewrite.

`read` and the analysis commands (`stats`, `expert`, `follow`, `tls`,
`dns-read`, `http`, `export`) also accept `--start-epoch`/`--stop-epoch` to
keep only frames inside an inclusive epoch-second window, written
`SECONDS[.FRACTION]` with up to nanosecond precision and compared exactly —
never rounded to the capture's own resolution. Either side may be open,
reversed bounds and fractions the host cannot represent exactly are rejected,
frames without timestamps are never kept, and skipped frames still count toward
the read limits. Selection follows the timestamp value, so out-of-order clocks
cannot escape the window.

`read --dissect` and `dissect` decode DNS answer, authority, and additional
records, including EDNS and exact unknown RDATA. Malformed or truncated DNS
messages produce diagnostics while retaining their captured bytes. The
[migration notes](docs/migration-unreleased.md#offline-dns-records) describe
the structured record fields and bounded core decoder.

## Install

[GitHub releases](https://github.com/tyk-swe/pcr/releases) provide Linux
x86-64 and Arm64, macOS x86-64 and Arm64, and Windows x86-64 MSVC archives.
Verify the matching archive with `SHA256SUMS`, then put `packetcraftr` or
`packetcraftr.exe` on `PATH`.

- `all-features` archives include routing, raw Layer 3, and Layer 2
  capture/injection. They require libpcap on Linux and macOS or Npcap 1.88 on
  Windows.
- `pcap-free` archives include routing and raw Layer 3 without libpcap/Npcap.

Release archives produced by the current workflow include GitHub Artifact
Attestations signed with Sigstore:

```console
gh attestation verify packetcraftr-v<version>-<target>-<variant>.<ext> --owner tyk-swe
```

To build from source, install the toolchain in `rust-toolchain.toml`; the same
supported version is declared in `Cargo.toml`. All-feature Linux builds also
need libpcap development files such as `libpcap-dev`.

Choose the source profile before building:

```console
# Offline construction/analysis and ordinary-socket DNS --tcp
cargo build --locked --release -p packetcraftr-cli --no-default-features
# Passive routes/interfaces and raw Layer 3 I/O, without libpcap
cargo build --locked --release -p packetcraftr-cli --no-default-features --features native-layer3
# Every native provider, including capture, Layer 2, and capture-ready exchanges
cargo build --locked --release -p packetcraftr-cli --all-features
./target/release/packetcraftr --version
```

Default features provide passive routes/interfaces. Capture, exchange and
capture-backed probes require the corresponding full-native provider; pcap-free
supports offline work, routing, raw Layer 3 send/replay, and direct TCP DNS. See
[Contributing](CONTRIBUTING.md) for the ordinary Cargo loop.

Release artifacts use these runtime baselines: Ubuntu 24.04 (glibc 2.39) on
x86-64 and Arm64, macOS 14 on arm64, macOS 15 on x86_64, and Windows Server 2022
on x86_64. Older systems are
not a tested binary baseline; build from source for another environment.
Full-native Linux needs the shared libpcap runtime (Ubuntu `libpcap0.8t64`);
Windows capture/Layer 2 needs a working Npcap installation exporting the symbols
required by the loader. Pcap-free archives do not require libpcap/Npcap.
`BUILD-METADATA.json` in each release archive records compiler, commit, target,
feature variant and the executable digest. Linux packaging also runs offline
smokes in a clean Ubuntu 24.04 container.

Read [analysis resources and evidence](docs/analysis-resources.md) for cumulative
versus concurrent limits, clock/filter semantics, cancellation and reproducible
whole-workflow memory measurements. Binary output refuses interactive stdout
unless `--force-binary-stdout` is supplied. For commands with cooperative
cancellation, the first interrupt requests cleanup;
the second forces exit. Cancellation exits 130; a killed process or unwritable
sink cannot promise a terminal NDJSON record.

## Shell completions and man pages

Release archives ship generated shell completions under `completions/` (Bash,
Elvish, Fish, PowerShell, and Zsh) and man pages under `man/` (one per command).
The binary itself regenerates both trees from the finalized command
definitions:

```console
packetcraftr documentation --directory DIR
```

This writes `DIR/completions/` and `DIR/man/`, which can be copied into the
shell completion and `man1` directories of the platform.

## Contracts

- Packet JSON/YAML: [`packetcraftr.packet/v2`](schemas/packetcraftr.packet.v2.schema.json)
- Structured command output: [`packetcraftr.output/v5`](schemas/packetcraftr.output.v5.schema.json)
- Published packet and output examples: [`examples/documents`](examples/documents)

Aggregate output consumers must ignore unknown fields in result objects and
nested output records. Shared records follow this rule in NDJSON too. Envelope
fields, enum vocabularies, and embedded packet documents remain strict. Changed
machine contracts receive a new schema version; packet documents and command
output are versioned independently.

Packet documents use bounded JSON/YAML parsing. Put the global `--output`
option before the command, for example `packetcraftr --output json stats
capture.pcapng`. Supported formats depend on the command and include `text`,
`json`, `ndjson`, `hex`, `raw`, `pcap`, `pcapng`, `csv`, and `tsv`; invalid
combinations fail explicitly. Every output-v5 NDJSON envelope has an `event`
discriminator; the schema enumerates the per-command event names, and
`complete` and `error` are the terminal records. The payload is in `result` or
`error`; consumers never need to
infer a record kind from payload fields. `sequence` starts at zero and advances
for each record. Successful operations end with exactly one `complete`; failed
operations emit one terminal `error` when the output is still writable. A broken
output is reported as incomplete on stderr and cannot guarantee a terminal line.
Packet documents use v2; consumers of earlier contracts must migrate.

Exit codes are part of the contract: 0 on success, 2 for an invalid invocation
or input (`cli`), 3 for a packet that cannot be built or dissected (`packet`),
4 when a native feature, backend, or privilege is unavailable (`capability`),
5 for a failed system or network operation (`io`), 6 when the traffic policy
denies the operation (`policy`), and 70 for an internal invariant failure.
The name in parentheses is the `error.kind` of the same failure in JSON and
NDJSON output; `packetcraftr --help` lists the table. `verify-forwarding`
exits 1 when its comparison completes but the verdict is `fail` or
`inconclusive`; the published `verdict` field distinguishes them, so a
completed report never pairs with a contradictory error record.

Offline `stats`, `expert`, `follow`, and `tls` perform bounded, capture-global
IPv4 and IPv6 fragment reassembly before downstream transport indexing. A
completed datagram is a derived view attached to the physical fragment that
completed it: `frame.*` fields and physical frame/byte totals remain captured
facts, while reconstructed child layers can satisfy display filters and join
TCP or UDP conversations. `stats --table fragments` reports physical fragment
and derived-datagram accounting separately. The shared `--ip-overlap`,
`--ip-idle-expiry-ms`, and `--max-ip-*` options make overlap behavior, expiry,
and every retained-state ceiling explicit.

`follow --stream tcp:N` and `follow --stream udp:N` exit with invocation error
2 when the selected conversation is absent, including in an empty capture.
Existing conversations with no payload still succeed with zero extracted bytes.

`follow --write DIR` saves each selected direction's payload as
`TRANSPORT-INDEX-client.bin` and `TRANSPORT-INDEX-server.bin` inside DIR —
`--direction` narrows which files are written, and an empty direction produces
an empty file. Files are staged in DIR and published atomically without
overwriting existing destinations; both share one
`--max-application-output-bytes` budget, and the aggregate report lists each
published path under `written`. Publishing is not a multi-file transaction: on
failure, staged bytes are discarded and rollback of already-published files is
attempted. Cleanup failures report the paths that could not be removed.

Every `stats` report carries a compact capture summary alongside the selected
table: the matched-timestamp `duration`, `average_packet_size`, and
`packets_per_second`/`bytes_per_second` rates (absent on empty match sets and
zero spans; timestamp regressions cannot produce a negative duration), plus
the `interfaces` the capture source declared, in the ID order frame records
reference. A PCAPNG file with no interface descriptions reports an empty
list rather than inventing one.

`expert` findings also cover capture-level evidence beyond TCP state:
`capture.frame_truncated` marks a record whose captured length falls short
of its wire length, and `capture.clock_regression` marks a matched frame
timestamped below the capture's high-water mark. Both carry the frame number
and, when the source declares one, the interface ID; both are warnings and
respect `--min-severity`, `--code`, and the retained-finding limit.

## Library

Depend on the crate that owns the capability you need:

| Crate | Ownership and entry points |
|---|---|
| `packetcraftr-core` | `Packet`, protocol codecs/reflection, bounded documents, capture files, filters, and `analysis::run` |
| `packetcraftr-netio` | Interface/route providers, capture/transmit resources, and platform backends |
| `packetcraftr` | `Client` preparation/send/exchange, `policy`, and DNS/replay/scan/traceroute/fuzz workflows |
| `packetcraftr-cli` | Arguments and rendering; its `output` module owns machine representations and the stream encoder |

Core is portable and independent of native I/O. A workflow uses one policy
implementation for operation admission and final-wire checks; resolver and
replay adapters add their specific boundaries. The CLI shares the same policy
instance with its authorizer and executor. `dns::Completion` and `dns::Report`
validate accepted transport and retained evidence at construction.

Offline analysis exposes a physical `FrameRecord` with optional `TcpView` and
`UdpView` observations. Each observation carries its decoded source and scoped
conversation together. Derived datagrams do not add physical frames or bytes.

Runnable examples live in their owning crates and use only documentation
addresses and in-memory fixtures — no native features or network access are
required:

```console
cargo run -p packetcraftr-core --example build_decode_filter
cargo run -p packetcraftr-core --example capture_analysis
cargo run -p packetcraftr --example client_composition --no-default-features
```

`client_composition` wires a `Client` over local route/neighbor/sender
providers under an explicit `Policy` (destination allowlist plus finite
per-operation packet/byte budgets) and shows both an admitted send and an
allowlist denial without emitting traffic.

```console
cargo doc --locked --workspace --all-features --no-deps --open
```

## Live Networking

Live operations enforce destination policy, hostname-resolution opt-ins,
permissive-packet and source-spoofing controls, route/interface and MTU checks,
finite packet/byte/time budgets, and native OS permission requirements. Only
applicable commands expose each control; read that command's `--help` instead
of copying flags between workflows.

`--allow-destination ADDRESS[/PREFIX]` restricts live destinations to exact
addresses or canonical CIDR networks and may repeat. The list is checked at
target authorization, on every route-bearing address a packet declares, and
again on the destination the final wire bytes actually carry. Constraints only
narrow permission — a public destination inside the allowlist still needs
`--allow-public-destinations`. Network entries must spell the canonical
network address (`192.0.2.0/24`, not `192.0.2.1/24`); an absent list adds no
constraint.

Time budgets are checked at workflow boundaries and passed to native I/O where
its interface accepts a deadline. Event publication bounds the caller's wait.
Synchronous provider, reader, and resolver calls use their own I/O timeouts;
workflow checks cannot interrupt them or arbitrary injected callbacks. Timed-out
workers retain their permits and resources until cleanup finishes.

| Platform | Requirements and notable limits |
| --- | --- |
| Linux | Layer 2 and raw Layer 3 usually require root or `CAP_NET_RAW`; complete builds need libpcap. Containers must expose the interface, route, and capability in the same namespace. |
| macOS | Layer 2 needs libpcap and BPF-device access; raw sockets usually require root. Complete-header raw IPv6 transmission is unsupported. |
| Windows | Layer 2 needs Npcap 1.88; raw sockets usually require administrator rights. Windows may reject raw UDP with a non-local source. |

For `capture`, `--capture-filter` is resolver-free native BPF applied before
PacketcraftR queues and budgets; `--filter` runs after capture.

By default, `dns` starts each attempt over UDP. A matching validated response
with the DNS truncation flag triggers one length-prefixed TCP continuation to
the same independently reauthorized numeric server. UDP and TCP share the
single `--timeout-ms` attempt window; TCP failures follow the normal retry
count. Output identifies both attempted phases and the transport of the
accepted response, without presenting socket bytes as captured frames. Use
`--udp-only` when transport diagnostics or compatibility require the previous
terminal-truncation behavior, or when packet-oriented `--interface`, `--source`,
or `--link-mode` overrides must be preserved. IPv6 link-local DNS servers also
require `--udp-only` because the target syntax does not carry a TCP scope ID.

`dns --tcp` starts each attempt directly over an ordinary TCP socket and works
in the portable profile without raw capture privileges. It uses the same
authorization, message limits, response checks, deadlines, and retry count.
Direct TCP reports `fallback_attempted=false`, socket bytes, and zero captured
packet counts. It uses an OS-selected local port; `--source-port`, `--udp-only`,
and packet-oriented route overrides cannot be combined with `--tcp`.

`dns` accepts several NAME positionals and repeatable `--reverse ADDRESS`,
which derives the PTR question under `in-addr.arpa` or `ip6.arpa` — a bounded
batch of at most 256 questions sharing the explicit server, transport
selection, and one `--max-duration-ms` deadline. Each question reports
`completed`, `failed`, or `unattempted` in input order; a question's own
attempts keep `--timeout-ms` and `--attempts`. `--transaction-id` stays
single-question only; batches generate a fresh identifier per question.

Library callers enable TCP by composing an exchange executor with
`.with_dns_tcp(provider)`. The CLI explicitly selects
`packetcraftr_netio::tcp::SystemProvider`; injected UDP executors default to
unsupported TCP execution. The standard-library TCP provider is available
independently of the native packet-I/O feature flags.

`--type` accepts `a`, `aaaa`, `caa`, `cname`, `mx`, `ns`, `ptr`, `soa`, `srv`,
`txt`, and `any`, or any decimal code in `0..=65535`, optionally prefixed with
`TYPE` (for example, `TYPE65`). Aliases and the prefix are case-insensitive.
JSON and NDJSON report `query_type` as the exact integer wire code; text keeps
named aliases and uses `TYPE<n>` for other codes.

`--edns-udp-payload-size SIZE` adds one EDNS v0 OPT record, with `SIZE` in
`512..=65535`. `--dnssec-ok` requires that setting and sets the DO bit to request
DNSSEC data; it does not enable signature validation. EDNS is disabled by
default. The advertised UDP receive size is independent of the
`--max-message-bytes` decoder ceiling.

Kernel TCP control and retransmission packets are OS-managed, so DNS
authorization does not mislabel them as an exact raw-packet count. It instead
charges bounded connection and framed-message traffic units, application
bytes, and duration, adding an exact UDP wire budget when UDP is selected.

`scan --transport udp` accepts `--udp-payload-hex HEX` or
`--udp-payload-file PATH`. The same exact payload is sent to each selected port,
up to 65,507 bytes, with derived lengths/checksums and the existing policy and
MTU checks. Empty payloads retain the previous behavior. Valid DNS payloads on
port 53, VXLAN payloads on port 4789, and Geneve payloads on port 6081
materialize as exact typed layers, including inner frames and their nested
destination checks; payloads that do not decode as their registered protocol
still need to satisfy strict construction. Responses retain transport and
ICMP-error correlation; payload selection does not add application-level
response assertions.

`replay --bps 8000000` selects a bit rate instead of captured intervals or
packets per second. It counts exact submitted frame bytes without synthetic
media overhead, sends the first selected frame immediately, and schedules
later frames from cumulative bytes already sent. Filtered frames consume no
bit-rate timing. Cumulative rounding avoids per-frame drift; scheduled duration
and byte totals describe the operation, without a throughput guarantee.

Replay maps input interfaces with `--map-interface SOURCE_ID=OUTPUT_INTERFACE`
or display filters with `--map-filter 'EXPR=>OUTPUT_INTERFACE'`. Source IDs are
capture-global; classic PCAP uses 0. `--interface` supplies an optional fallback.
Conflicting mappings and selected frames without a destination fail before that
frame can transmit. Every selected frame retains endpoint and final-byte checks.
`--repeat 1..1024` and `--inter-pass-delay-ms` repeat a validated capture snapshot.
Timing restarts each pass, while source-frame, transmitted-byte, policy, and time
budgets span the whole operation. Events identify the pass and actual interface.

`scan` accepts multiple IP addresses, hostnames, and CIDRs, with repeatable numeric
`--exclude IP_OR_CIDR` and a shared `--max-targets` ceiling. Selection deduplicates
in input order and rejects oversized networks before expansion. Hostname lookup
requires the existing policy opt-in; selected endpoints are authorized before
probe execution. CIDRs include every numeric address in their range.

`scan --connect --ports 80,443` uses ordinary TCP sockets and works in the portable
build. `--max-in-flight` permits up to 16 overlapping connections; one pacing
schedule and deadline bound the run. Results distinguish connected, refused,
timeout, unreachable, and local failures, and report socket-call evidence.
The kernel controls TCP wire packets. Packet route overrides are rejected for
this mode, and cancellation retains resource admission until cleanup finishes.

Both scan paths report bounded repeated-probe statistics in `rtt`: `sent` counts
confirmed probe transmissions (admitted connect calls for `--connect`),
`received` counts probes that produced a definitive verdict inside their round —
a checksum-valid correlated response, or a connected, refused, or unreachable
socket verdict — and `lost` is `sent - received`. `min`/`avg`/`max` summarize
one round-trip sample per received probe and are absent when nothing answered.
Duplicate replies inside one round contribute a single sample; replies carrying
a stale identity never correlate. A capture backend reporting dropped frames
marks the caveat with the `capture.evidence_incomplete` diagnostic.

This documentation-address example only prints help and performs no network
operation:

```console
packetcraftr dns 192.0.2.53 example.test --udp-only --help
```

## Contributing, Security, and License

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance. Report
suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

PacketcraftR is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE). Bundled dependency
attributions are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

### Structured fixtures, fragmentation, and capture processing

Packet recipes use `packetcraftr.packet/v2`; command JSON/NDJSON uses
`packetcraftr.output/v5`. Named objects, `hex("00ff")`, and `bytes("text")`
can appear inside expressions and nested template axes.

```sh
packetcraftr build --packet-file examples/documents/packet-dns-response.json
packetcraftr build --packet-file examples/documents/packet-tls-client-hello.json
packetcraftr --output pcapng fragment --packet 'ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=40000,dport=40001)/raw(text=fixture)' --mtu 32 > fragments.pcapng
packetcraftr merge left.pcap right.pcapng --write merged.pcapng --compression zstd
packetcraftr --output pcap read capture.pcap.gz --compression zstd > capture.pcap.zst
packetcraftr --output csv read capture.pcapng --field frame.number --field ip.src --field udp.source_port
```

Fragmentation is explicit and never sends traffic. MTU excludes the link header.
IPv4 DF and existing fragments are rejected; IPv6 splitting requires
`--identification` and enough room for its complete first-fragment header chain.
The transform supports raw IP and Ethernet/VLAN, preserves transport bytes and
capture time, regenerates Ethernet padding, and omits link trailers/FCS.
AH/ESP and unsupported IPv6 upper-layer headers are explicit errors.

Merge requires time-ordered inputs and rejects missing/regressing timestamps.
Equal times use input argument order and source frame order. Output interfaces
remain distinct by source/section/interface; generated interface comments retain
that mapping. Source-only sections, statistics, comments, and unknown metadata
are normalized away. Extended FCS/packet-flag metadata is currently rejected.
The destination must be new and is published only after successful finalization.

Capture readers detect gzip/Zstd by magic, including redirected stdin and replay
files. Binary capture output supports `--compression none|gzip|zstd`.
`--max-encoded-bytes` and `--max-decoded-bytes` each default to 256 MiB per
input; decoded accounting includes metadata. Empty compressed members and
skippable frames consume the encoded budget. Zstd windows are capped at 64 MiB.
Concatenated members are decoded and truncation/corruption fails the operation.

`read` and `dissect` accept repeatable `--field` selections. Columns preserve
request order, absent values are `null`, and repeated layers produce ordered
arrays. `protocol#N.field` selects a one-based layer occurrence; list indices
such as `dns.questions[0].name` are zero based. Bytes render as lowercase hex.
CSV/TSV cells contain compact JSON values with CSV-style quoting; headers are
field names. JSON and NDJSON include source frame identity and completion counts.
Projection data is bounded by `--max-projection-bytes` (16 MiB by default),
excluding structured envelopes. Stream-index fields in `read` use bounded capture
analysis and require timestamped input; `dissect` cannot assign stream indexes.

Offline DNS inspection uses `dns-read CAPTURE` with text, JSON, or NDJSON output.
It accepts gzip and Zstd captures and additional `--dns-port` values. TCP prefixes
and bodies may cross segments, and one delivery may contain several messages.
`--stream tcp:INDEX` or `--stream udp:INDEX` selects a complete conversation.
Every message and transaction lists its physical source frames and timestamps,
including fragments needed to reconstruct an IP datagram. Per-frame `dns` fields
also decode a complete first TCP message; use `dns-read` for stream boundaries.

Transactions match capture scope, transport, connection generation, reversed
endpoints, ID, opcode, and the complete question set (ASCII case-insensitive DNS
names). Query retries share one outstanding transaction; a new query after a
response starts a new transaction even if its ID is reused. Empty or mismatched
response questions remain orphan evidence. A missing response means it was not
captured. Latencies run from the last physical query frame to the first physical
response frame; first-query and latest-retry values include a negative-interval
flag. A response can precede query completion when reassembly fills a late gap;
that interval is kept as captured. TCP gaps, conflicting retransmissions, resets, malformed messages, and
partial capture endings remain explicit. Application message, stream, source,
buffer, retained-byte, and output-byte ceilings are finite and configurable.

Use `http CAPTURE` to inspect cleartext HTTP/1.0 and HTTP/1.1 messages over TCP.
The collector handles split headers, request pipelining, interim responses, HEAD,
content lengths, chunked bodies and trailers, and clean-close-delimited bodies.
CONNECT success and protocol upgrades end HTTP inspection for that connection.
Bodies are counted without being retained or decompressed. Duplicate headers,
exact header wire, binary values, source frames, and request links remain in
JSON/NDJSON. Gaps, resets, capture endings, invalid framing, and body limits are
explicit outcomes. HTTP/2, HTTP/3, TLS decryption, and object extraction remain
outside this command. `--http-port` adds a cleartext service to ports 80 and 8080;
`--stream tcp:INDEX` selects a whole conversation. The per-frame `http` layer and
`--decode-as tcp.port=PORT:http` expose headers that fit in one captured segment.

`export CAPTURE --stream tcp:INDEX --write selected.pcap` copies a whole scoped
conversation, including the physical fragments used to reconstruct its transport
packets. Stream selectors repeat; `--datagram-frame NUMBER` selects complete or
incomplete IP groups containing that physical frame. `--filter EXPR` selects
physical/derived fields and includes datagrams reconstructed on matching records.
The saved file retains the source format, packet records, interface identity,
timestamps, and metadata; PCAPNG section lengths become unknown and interface
statistics continue to describe the source capture. `--compression gzip|zstd`
compresses the result. Input is validated into a bounded anonymous snapshot, then
analyzed and copied from that same snapshot. A new output path is published only
after every pass succeeds. Reports list source positions, unmatched selectors,
known incomplete dependencies, unattributable groups, and omitted source outcomes.
Missing fragment headers are never used to guess a conversation. Ordinary `read`
keeps its existing physical-frame selection behavior.

`rewrite CAPTURE --write rewritten.pcapng` edits matched capture headers. Direct
options include `--source-ip`, `--destination-ip`, TCP/UDP source/destination
ports, MAC addresses, repeated `--vlan VID` (or `TPID:VID:PRIORITY:DEI`), and
`--strip-vlans`. `--filter` matches original frame fields. For conditional edits
in both directions, use `--rules-file examples/documents/rewrite-lab-host.json`.
The bounded `packetcraftr.rewrite/v1` document applies matching patches in order;
every condition sees the original frame. The rule schema is shipped alongside
packet and output schemas.

Rewriting keeps application bytes, capture time, direction, and interface identity.
VLAN replacement changes frame lengths by the tag-size difference; IP lengths
stay faithful and affected checksums are recalculated. IPv4 UDP checksum zero
remains disabled. Network/port edits reject truncated or non-atomic fragmented
packets, unsupported checksum semantics, source-routing/Home Address headers, and
authenticated headers. MAC/VLAN-only edits can operate on fragments. The saved
PCAPNG uses one section, retains interface options, and discards source section
structure, packet options, statistics, and other non-interface metadata. Missing
timestamps, declared FCS metadata, and extended packet flags fail explicitly.
Interface snapshot ceilings account for possible VLAN growth. Existing output
paths are preserved; compression is finalized before publishing the new file.

DHCP fixture construction and inspection use `dhcpv4` (`dhcp`) and `dhcpv6`
(`dhcp6`) below UDP. Standard ports are 67/68 and 546/547; `--decode-as` also
supports both protocols. Named options expose transaction IDs, assigned addresses,
lease timers, server/client identifiers, DNS servers, DUIDs, nested IA_NA/IA_PD
options, prefixes, and relay messages. DHCPv4 overloaded `file`/`sname` areas are
parsed and constructible; their use is derived when option lists are supplied.
See `examples/documents/packet-dhcpv4-offer.json` and
`examples/documents/packet-dhcpv6-reply.json` for bounded recipes. The wire formats
are described in [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131),
[RFC 2132](https://datatracker.ietf.org/doc/html/rfc2132), and
[RFC 9915](https://datatracker.ietf.org/doc/html/rfc9915).

Unedited decoded messages retain their exact wire image. Unknown and noncanonical
option bodies remain raw; DHCPv4 concatenation pieces are preserved separately.
Malformed TLV lengths remain available through the dissection's malformed bytes.
DHCPv6 legacy IA_TA and Server Unicast options remain readable for older captures.
Decoders and constructors share finite message, option-count, and nesting limits.
These codecs provide no DHCP server, address configuration, or active discovery.
Repeated child descriptions in `protocols --output json` use `children_reference`,
a JSON Pointer anchored at their top-level field description, keeping recursive
DHCP metadata compact without limiting nested field paths.

Live capture accepts repeated `--interface` selections. It partitions the native
queue limits across the selected interfaces, waits for every source to become
ready, and applies one frame/byte/window budget across the operation. Records keep
capture timestamps and fair delivery order. Capture IDs start at zero in selected
interface order; completion metadata maps them to native names/indexes and reports
per-interface delivery, filtering, loss, and cleanup. Use PCAPNG for multiple
interfaces; classic PCAP remains available for one interface on stdout.

`capture --write trace.pcapng --rotate-bytes 1048576 --rotate-files 4` saves bounded
PCAPNG files. `--rotate-interval-ms` adds monotonic time boundaries between frames.
Byte thresholds include uncompressed headers and interface metadata; a frame that
cannot fit in an empty file fails before its bytes are written. JSON summaries
require `--write`; text and NDJSON can also report saved captures. `--retention stop`
is the default. Explicit `--retention ring` reuses only file handles created by
this operation, and reports retired generations/frames. Existing paths remain
untouched. Numbering is inserted before the last filename extension. Compression
finishes independently for every file. Rotation and interfaces never reset the
operation budget. A final boundary can consume a matched frame without publishing
it; admitted/matched/emitted counts make that distinction visible. Failure output
retains partial source and file evidence, including finalization state.

`capture --dissect` decodes each emitted frame once and prints its layer list in
text or adds a `decoded` object — packet document, layout, and diagnostics — to
NDJSON `frame` records beside the preserved captured bytes. `capture --field`
streams bounded `fields` rows per matched frame under `--max-projection-bytes`,
sharing the `read`/`dissect` projection contract. Decoded output requires text
or NDJSON, decodes a frame at most once across `--filter` selection and
emission, honors `--decode-as`/`--tls-port` bindings, and never accumulates
decoded state across frames.

Raw scans accept `--max-in-flight` for bounded rolling response windows. The client
validates the complete plan before active discovery, shares ready capture sessions
by interface, checks final bytes/endpoints, and uses one rate/deadline/evidence
budget. Preparation is bounded by `--max-prepared-bytes`; large packet descriptions
can reduce the active window below its requested ceiling. NDJSON `probe_sent`
records preserve accepted wire before final probe outcomes. Pipeline failures carry
confirmed pending receipts and source cleanup evidence in `error.scan`.

`scan ... --transport udp --udp-profiles examples/documents/udp-profiles.json`
selects named per-port requests and response checks. Profiles generate typed DNS
queries with per-probe IDs, or transmit explicit bytes under operation-local raw
bindings. Responses can be checked against DNS IDs/questions or bounded masked byte
patterns. `application.status` distinguishes confirmed, rejected, unchecked, and
unobserved application evidence from transport reachability. A matching profile is
not authenticated service identity. Unmapped ports preserve the ordinary payload
fallback. Profile files use `packetcraftr.udp-profiles/v1`, are capped at 1 MiB,
and never resolve the DNS question name merely to construct its wire bytes.
