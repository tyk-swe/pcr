# PacketcraftR

PacketcraftR is a Rust library and CLI for protocol development,
interoperability testing, and authorized network diagnostics. It provides
exact packet construction, bounded dissection, capture-file I/O, offline
analysis, and policy-gated live networking.

Latest release: pre-1.0 beta `0.5.0-beta.3`. This README describes `main`, which
carries unreleased breaking changes to the packet and output contracts. Rust
APIs and versioned serialized contracts may change between beta releases;
review the [changelog](CHANGELOG.md) and the migration note for your upgrade:
[beta.3](docs/migration-beta.3.md) for the current release, or
[unreleased changes](docs/migration-unreleased.md) for `main`.

> **Authorized use:** PacketcraftR is designed for controlled labs, protocol
> testing, and diagnostics on systems and networks you own or are explicitly
> authorized to test. Its opt-in flags are technical controls, not permission.

## Start with a task

[Build and verify a fixture](docs/tasks.md#1-build-a-fixture-and-test-one-property),
[investigate a capture](docs/tasks.md#2-investigate-a-capture-without-losing-evidence),
or [run an authorized isolated diagnostic](docs/tasks.md#3-run-an-authorized-diagnostic-in-an-isolated-lab).
For automation, start with the [forwarding contract](docs/verification-contract.md),
[versioned resource presets](docs/resource-presets.md), and
[consumer compatibility policy](docs/consumer-compatibility.md).
For planned scanner capabilities, see the [core scanner roadmap](docs/roadmap/README.md)
and its [Nmap gap matrix](docs/roadmap/nmap-gap-matrix.md); the
[evidence vocabularies](docs/scanner-evidence.md) and
[scanner data policy](docs/scanner-data-policy.md) govern what scan output may
claim and what data the scanner may ship.

## Quick start

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
packetcraftr --output hex build --packet 'ipv4()/icmpv4(identifier=1)' \
  | packetcraftr dissect --link-type ipv4 --hex - --tree
packetcraftr --output pcap build --session tcp --link-type ethernet \
  --packet 'ethernet()/ipv4(src=192.0.2.1,dst=198.51.100.2)/tcp(sport=40000,dport=80)/raw(text=ping)' \
  > conversation.pcap
packetcraftr topics filters
```

The `tls` example assembles ClientHello and ServerHello records across TCP
segments and reports SNI, negotiated parameters, JA3/JA3S/JA4, and status.
Use `packetcraftr --help`, `packetcraftr <COMMAND> --help`, and
`packetcraftr protocols [PROTOCOL]` for the authoritative command, option, and
protocol catalogs. Each command's `--help` ends with examples. `packetcraftr
topics` lists the built-in references: `topics expressions` for the packet
expression grammar, `topics filters` for the display-filter language, and
`topics formats` and `topics exit-codes`. `build --session tcp|udp` expands one
client-to-server packet into a deterministic conversation (handshake,
MSS-sized segments with ACKs, an optional `--session-response-file` reply, and
a close) of at most 4096 frames, byte-identical for equal inputs, for fixture
captures.

Recipe commands such as `build` read a packet expression, JSON, or YAML from
redirected stdin when neither `--packet` nor `--packet-file` is supplied. The
capture readers `read`, `expert`, `follow`, `stats`, `tls`, `dns-read`, `http`,
`http2`, `export`, `rewrite`, `verify-forwarding`, and `merge` accept `-` as a capture
path to stream PCAP or PCAPNG from redirected stdin, for example
`packetcraftr --output ndjson read - < examples/captures/tls-handshake.pcapng`.
`merge` and `verify-forwarding` accept stdin for at most one input. Files and
pipes share the same limits, terminal stdin is rejected, and live `replay`
remains file-based. Stdin reads are synchronous: a duration limit is checked
between reads and cannot interrupt one that is waiting for input.

| Area | Commands |
| --- | --- |
| Packets and captures | `build`, `dissect`, `protocols`, `read` |
| Capture transformation | `fragment`, `merge`, `export`, `rewrite` |
| Offline analysis | `expert`, `follow`, `stats`, `tls`, `dns-read`, `http`, `http2`, `verify-forwarding`, `fuzz` |
| Native inspection and planning | `interfaces`, `routes`, `plan` |
| Live workflows | `send`, `exchange`, `capture`, `replay`, `scan`, `traceroute`, `dns`, `fuzz --live` |
| References and shell integration | `topics`, `documentation` |

## Packet sets, decode-as, and capture selection

`build`, `exchange`, and `send` accept repeatable `--axis` selections over
layer fields, as an expression list or an inclusive range such as
`ipv4.ttl=1..64:8`. A layer is named by protocol with an optional one-based
`#occurrence` (`ipv4#2.ttl` is the inner IPv4 header of a tunnel) or by
zero-based index (`0.ttl`), and protocol names are case-insensitive:

```console
packetcraftr --output ndjson build --packet 'ipv4(dst=192.0.2.1)/udp()' --axis '0.ttl=[1,64]' --axis '1.dport=[9000,9001]'
```

This produces four packets in Cartesian order, with the last axis varying
fastest; `--max-template-packets` (default 10,000) is checked before any packet
is prepared. `exchange` applies one budget and response window to the whole
set (`--stop-when-answered` ends the window once every request has a response),
and `send --repeat N` with `--rate N` replays the expansion under one finite
packet/byte budget. Every frame's endpoints and final bytes are checked before
it is sent.

`build --set ipv4.ttl=5` overrides a recipe field by the same selectors
(repeatable, at most 64, applied in order before axes expand), and generators
such as `repeat(0x41,1400)`, `zeros(64)`, and `cyclic(40)` fill bytes values
alongside `0b`, `0o`, and underscore-separated integers. `fuzz --field` takes
the same selectors, plus `*` for the protocol or the field.

`--decode-as 'udp.port=5300:dns'` binds a port to a codec for decoding and
display filters. It is accepted by `dissect`, `read`, `follow`, `stats`,
`expert`, `tls`, `dns-read`, `http`, `http2`, `export`, `rewrite`,
`verify-forwarding`, and `capture`. TCP ports support `dns`, `http`, `tls`, and `raw`; UDP ports
support `dhcpv4`, `dhcpv6`, `dns`, `ntp`, `vxlan`, `geneve`, `gtpu`, `tftp`,
`syslog`, and `raw`. UDP 53, 5353 (mDNS), and 5355 (LLMNR) already decode as
DNS, and TFTP transfers, which leave port 69, need `--decode-as
'udp.port=N:tftp'`. A mapping overrides the built-in binding for that port,
conflicting declarations are rejected, and at most 256 declarations and 64 KiB
of mapping text are accepted. `--tls-port 4433` is shorthand for
`--decode-as 'tcp.port=4433:tls'`.

Display filters (`--filter`, described by `packetcraftr topics filters`) take
comparisons, sets, prefixes, and inclusive ranges (`udp.dstport in
1024..65535`), masks (`tcp.flags & 0x12 == 0x12`), the text operators
`contains`, `startswith`, `endswith`, `icontains`, and `iequals`, escapes and
`b"..."` byte strings, list selectors (`dns.answers[*].type == 1`,
`dns.answers[-1].ttl > 20`), `len()` and `count()`, `#last` layer occurrences,
and `frame.*` facts. Two limits apply: a text operator on a list of numbers or
addresses, such as `dns.qtype`, compiles but never matches (a list of objects,
such as `tcp.options`, is a compile error), and `frame.reassembled` is not a
field.

Save a focused capture in the source format (`--output` must match it), or use
`--normalize` to export either capture format as PCAPNG or as classic PCAP:

```console
packetcraftr --output pcapng read capture.pcapng --filter 'udp.port == 53' > dns.pcapng
packetcraftr --output pcapng read capture.pcap --normalize --filter 'udp' > selected.pcapng
packetcraftr --output pcap read capture.pcapng --normalize > single-interface.pcap
packetcraftr --output pcapng read capture.pcapng --frames 1-100,250,300- --every 5 > sample.pcapng
```

Selected records keep their original bytes, timestamps, and options; PCAPNG
section lengths become unknown and interface statistics still describe the
source capture. Filters use original frame numbers and do not pull in related
packets or fragments; use `export` for whole conversations. `--normalize`
writes one new section with remapped interfaces and discards comments, unknown
blocks and options, and the original section structure. It refuses a capture
that declares a frame check sequence, which the new section cannot record. It
never invents times, so a selected frame without an exactly representable
timestamp fails.
`--normalize --output pcap` writes classic PCAP instead, which holds one link
type and no interface or direction metadata: the selection must share one
interface, carry no packet direction, have timestamps in the source's
nanosecond or microsecond resolution, fit the source snapshot length, and not
be empty, and anything else fails rather than being rounded. `--frames
2-3,10` (also `10-`) and `--every 5` select frames by one-based source position
in every `read` path, and combine with `--filter` and the epoch window; frames
that are skipped keep their frame and stream numbers.
All input frames, including filtered-out ones, count toward the finite frame
and byte limits. An empty selection is a valid capture, errors can leave partial
output, and without `--filter` or `--normalize` output is a byte-for-byte
rewrite.

`read`, `stats`, `expert`, `follow`, `tls`, `dns-read`, `http`, `http2`,
`export`, and `verify-forwarding` accept `--start-epoch` and `--stop-epoch`,
an inclusive epoch-second window written `SECONDS[.FRACTION]` with up to
nanosecond precision and compared exactly. Frames without timestamps are never
kept, and skipped frames still count toward the read limits.

`read --dissect` and `dissect` decode DNS answer, authority, and additional
records, including EDNS and exact unknown RDATA; malformed or truncated DNS
messages produce diagnostics while retaining their captured bytes. The
[migration notes](docs/migration-unreleased.md#offline-dns-records) describe
the structured record fields and bounded core decoder.

`dissect` reads frame bytes from `--hex`, from redirected stdin with `--hex -`,
from `--hex-file PATH`, or from `--file`, so `packetcraftr --output hex build
... | packetcraftr dissect --hex -` works; hex text may carry `0x` prefixes and
whitespace, colon, or dash separators. `--link-type` takes names such as `ipv4`
or `ethernet` as well as numbers, and `--tree`, which `read --dissect` and
`capture --dissect` also accept, prints each layer's fields as an indented tree
in text output.

## Install

[GitHub releases](https://github.com/tyk-swe/pcr/releases) provide Linux
x86-64 and Arm64, macOS x86-64 and Arm64, and Windows x86-64 MSVC archives.
Verify the matching archive with `SHA256SUMS`, then put `packetcraftr` or
`packetcraftr.exe` on `PATH`.

- `all-features` archives include routing, raw Layer 3, and Layer 2
  capture/injection. They require libpcap on Linux and macOS or Npcap 1.88 on
  Windows.
- `pcap-free` archives include routing and raw Layer 3 without libpcap/Npcap.

Release archives include GitHub Artifact Attestations signed with Sigstore:

```console
gh attestation verify packetcraftr-v<version>-<target>-<variant>.<ext> --owner tyk-swe
```

Release artifacts use these runtime baselines: Ubuntu 24.04 (glibc 2.39) on
x86-64 and Arm64, macOS 14 on arm64, macOS 15 on x86_64, and Windows Server 2022
on x86_64. Older systems are not a tested binary baseline; build from source for
another environment. Full-native Linux needs the shared libpcap runtime (Ubuntu
`libpcap0.8t64`); Windows capture/Layer 2 needs a working Npcap installation
exporting the symbols required by the loader. `BUILD-METADATA.json` in each
archive records compiler, commit, target, feature variant, and the executable
digest.

### Build from source

Install the toolchain in `rust-toolchain.toml`; the same supported version is
declared in `Cargo.toml`. Builds with Layer 2 support on Linux also need libpcap
development files such as `libpcap-dev`. Choose a profile, then build with
`cargo build --locked --release -p packetcraftr-cli` plus its Cargo arguments:

| Profile | Cargo arguments | Capability |
| --- | --- | --- |
| Portable | `--no-default-features` | Offline construction and analysis, ordinary-socket `dns --tcp` and `scan --connect`; native packet and route providers report unavailable |
| Default | none | Portable capabilities plus passive interface enumeration and route lookup |
| Layer 2 only | `--no-default-features --features native-layer2` | Default capabilities and Layer 2 capture/injection |
| Pcap-free | `--no-default-features --features native-layer3` | Default capabilities and raw Layer 3 `send`/`replay`, without libpcap |
| Full native | `--all-features` | Every provider, including capture, Layer 2, and capture-ready exchanges |

Capture, `exchange`, and capture-backed probes need a profile with Layer 2
capture. Verify a build with `./target/release/packetcraftr --version`, and see
[Contributing](CONTRIBUTING.md) for the ordinary Cargo loop.

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
- Structured command output: [`packetcraftr.output/v9`](schemas/packetcraftr.output.v9.schema.json)
  (the frozen [`v6`](schemas/packetcraftr.output.v6.schema.json),
  [`v7`](schemas/packetcraftr.output.v7.schema.json), and
  [`v8`](schemas/packetcraftr.output.v8.schema.json) families are retained for
  previously published evidence)
- Capture rewrite rules: [`packetcraftr.rewrite/v2`](schemas/packetcraftr.rewrite.v2.schema.json)
- UDP scan profiles: [`packetcraftr.udp-profiles/v1`](schemas/packetcraftr.udp-profiles.v1.schema.json)
- Bundled scanner data: the [port catalog](crates/packetcraftr/data/port-catalog.json)
  (`packetcraftr.port-catalog/v1`) and
  [curated UDP payloads](crates/packetcraftr/data/udp-payloads.json), each with
  a provenance record and an independent data version that scan results name
- Published packet and output examples: [`examples/documents`](examples/documents)

These are the versions on `main`; release `0.5.0-beta.3` publishes only
`packetcraftr.packet/v1` and `packetcraftr.output/v2` (see the migration notes
linked at the top). Each contract is versioned independently, and a changed
machine contract receives a new schema version.

Aggregate output consumers must ignore unknown fields in result objects and
nested output records. Shared records follow this rule in NDJSON too. Envelope
fields, enum vocabularies, and embedded packet documents remain strict.

Put the global `--output` option before the command, for example
`packetcraftr --output json stats capture.pcapng`. Supported formats depend on
the command and include `text`, `json`, `ndjson`, `hex`, `raw`, `pcap`,
and `pcapng`; invalid combinations fail explicitly, and
`packetcraftr topics formats` lists which commands offer each. Every NDJSON
envelope has an `event` discriminator, and the schema enumerates the per-command
event names. `complete` and `error` are the terminal records, with the payload
in `result` or `error`, so consumers never need to infer a record kind from
payload fields. `sequence` starts at zero and advances for each record.
Successful operations end with exactly one `complete`; failed operations emit
one terminal `error` when the output is still writable. A broken output is
reported as incomplete on stderr and cannot guarantee a terminal line. Repeated
child descriptions in `protocols --output json` use `children_reference`, a JSON
Pointer anchored at their top-level field description.

Exit codes are part of the contract: 0 on success, 2 for an invalid invocation
or input (`cli`), 3 for a packet that cannot be built or dissected (`packet`),
4 when a native feature, backend, or privilege is unavailable (`capability`),
5 for a failed system or network operation (`io`), 6 when the traffic policy
denies the operation (`policy`), 70 for an internal invariant failure, and 130
for cancellation. The name in parentheses is the `error.kind` of the same
failure in JSON and NDJSON output; `packetcraftr --help` lists the table.
`verify-forwarding` exits 1 when its comparison completes but the verdict is
`fail` or `inconclusive`; the published `verdict` field distinguishes them.

For commands with cooperative cancellation, the first interrupt requests
cleanup and the second forces exit. A killed process or unwritable sink cannot
promise a terminal NDJSON record. Binary output refuses interactive stdout
unless `--force-binary-stdout` is supplied. Read
[analysis resources and evidence](docs/analysis-resources.md) for cumulative
versus concurrent limits, clock and filter semantics, and reproducible
whole-workflow memory measurements.

## Offline analysis and capture processing

Offline `stats`, `expert`, `follow`, and `tls` perform bounded, capture-global
IPv4 and IPv6 fragment reassembly before downstream transport indexing. A
completed datagram is a derived view attached to the physical fragment that
completed it: the capture-record `frame.*` facts (`frame.number`, `frame.len`,
`frame.cap_len`, `frame.interface_id`, `frame.link_type`, `frame.time_epoch`,
`frame.time_nsec`, `frame.direction`, and `frame.truncated`) and physical
frame/byte totals remain captured facts, while reconstructed child layers can
satisfy display filters and join TCP or UDP conversations. `frame.layer_count`
and `frame.protocols` are decoded facts, read from what the decoder produced
rather than from the capture record, so a truncated capture can show fewer
layers than the wire carried. `stats --table fragments` reports physical
fragments and derived datagrams separately, and the shared `--ip-overlap`,
`--ip-idle-expiry-ms`, and `--max-ip-*` options make overlap behavior, expiry,
and every retained-state limit explicit.

`follow --stream tcp:N` or `udp:N` exits 2 when the selected conversation is
absent, and `follow --write DIR` requires an existing writable directory and
publishes each selected direction atomically as
`TRANSPORT-INDEX-client.bin` or `-server.bin` without overwriting, bound to the
directory selected before input is read. Every `stats`
report carries a capture summary (`duration`, `average_packet_size`, packet and
byte rates, and the declared `interfaces`), and `expert` also reports the
capture-level warnings `capture.frame_truncated` and `capture.clock_regression`.
It also reports TCP handshake and sequence findings across frames, such as
`tcp.connection_refused`, `tcp.handshake_unanswered`, `tcp.out_of_order`, and an
Info `tcp.not_closed_at_end`. Only four open sequence gaps per direction are
watched, a handshake after an idle expiry is judged against the expired SYN, and
findings cover only frames that pass `--filter`, so filter by stream or host
pair rather than by one direction.
Analysis separates inner flows by encapsulation identifiers such as VLAN IDs,
VXLAN and Geneve VNIs, and GRE keys, but GTP-U and EtherIP have none yet, so
identical inner tuples between the same outer IP pair in different TEIDs or
EtherIP tunnels share one scope and stream.

Sample commands for fixtures and capture processing; each command's `--help`
lists its options, limits, and further examples:

```sh
packetcraftr build --packet-file examples/documents/packet-dns-response.json
packetcraftr --output pcapng fragment --mtu 32 --packet 'ipv4(src=192.0.2.1,dst=192.0.2.2)/udp(sport=40000,dport=40001)/raw(text=fixture)' > fragments.pcapng
packetcraftr merge --write merged.pcapng.zst --compression zstd first.pcapng second.pcap
packetcraftr merge --write all.pcapng --order append first.pcapng second.pcapng
packetcraftr merge --write sorted.pcapng --max-reorder-frames 64 multiqueue.pcapng
packetcraftr --output pcap read capture.pcap.gz --compression zstd > capture.pcap.zst
packetcraftr --output json read capture.pcapng --field frame.number --field ip.src --field udp.source_port
packetcraftr dns-read capture.pcapng --dns-port 5353 --stream udp:3
packetcraftr http examples/captures/http-stream.pcap
packetcraftr http2 examples/captures/http2-multiplexed.pcapng
packetcraftr export capture.pcapng --write conversation.pcapng --stream tcp:4
```

- `fragment` never sends traffic; `--mtu` excludes the link header. `merge`
  interleaves inputs by timestamp and needs each input time-ordered, unless
  `--max-reorder-frames N` (up to 65536) gives it a bounded look-ahead window
  that repairs small inversions, also for a single input, or `--order append`
  writes the inputs whole in argument order and keeps timestamps verbatim, so
  regressing captures merge and the output may be non-monotonic (the two
  options conflict). It publishes only a new destination.
- Capture readers detect gzip and Zstd by magic, including redirected stdin,
  and binary capture output takes `--compression none|gzip|zstd`.
- `dns-read`, `http`, `http2`, and `export` select a whole scoped conversation with
  `--stream tcp:INDEX` (`udp:INDEX` too, except for `http` and `http2`), including the
  fragments that rebuilt its packets. `http` covers cleartext HTTP/1 only;
  `http2` covers cleartext HTTP/2 and h2c upgrades -- encrypted TLS traffic is
  unsupported, never decrypted.
- `dhcpv4` (`dhcp`) and `dhcpv6` (`dhcp6`) build and dissect DHCP below UDP; see
  `examples/documents/packet-dhcpv4-offer.json`,
  `examples/documents/packet-dhcpv6-reply.json`, and
  [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131),
  [RFC 2132](https://datatracker.ietf.org/doc/html/rfc2132), and
  [RFC 9915](https://datatracker.ietf.org/doc/html/rfc9915). The codecs provide
  no DHCP server, address configuration, or active discovery.

`rewrite` edits capture headers with checked lengths and transport checksums.
Direct options cover MAC and IP addresses, TCP/UDP ports, repeated `--vlan VID`
or `--vlan TPID:VID[:PRIORITY[:DEI]]`, and `--strip-vlans`. `--set FIELD=VALUE`
instead assigns one fixed-width field in place (`ipv4.ttl`,
`ipv4.identification`, `ipv4.dscp_ecn`, `ipv6.hop_limit`, `tcp.sequence`,
`tcp.acknowledgment`, `tcp.window`, TCP/UDP ports, `icmp.identifier` and
`icmp.sequence` (and the `icmpv6` forms), `dns.id`, `dhcpv4.transaction_id`,
`vxlan.vni`, and `geneve.vni`); IPv4, TCP, UDP, and ICMP checksums are repaired
unless `--checksum-mode preserve` keeps checksum bytes exactly, and `--dry-run`
reports the changes without writing. `--map-ip OLD=NEW` and `--map-mac OLD=NEW`
remap addresses many-to-many instead: an IP side may be an address or an
equal-length prefix whose host bits carry over, the outer source and
destination are matched independently, at most 4096 entries are accepted, and
overlapping prefixes are refused. `--rules-file` applies ordered conditional
`packetcraftr.rewrite/v2` field-assignment rules, with at most 1 MiB and 64
rules. The output is one PCAPNG section that keeps application bytes, capture
time, direction, and interface identity, published only when every frame
rewrote cleanly.

```sh
packetcraftr rewrite capture.pcapng --write rewritten.pcapng --destination-ip 192.0.2.10
packetcraftr rewrite capture.pcapng --write out.pcapng --set ipv4.ttl=64 --filter 'udp'
packetcraftr rewrite capture.pcapng --write out.pcapng --set dns.id=7 --dry-run
packetcraftr rewrite capture.pcapng --write out.pcapng --set icmp.identifier=7 --set icmp.sequence=9
packetcraftr rewrite capture.pcapng --write out.pcapng --map-ip 192.0.2.0/24=198.51.100.0/24 --map-mac 02:00:00:00:00:01=02:00:00:00:00:02
packetcraftr rewrite capture.pcapng --write out.pcapng --rules-file examples/documents/rewrite-field-edits.json
```

## Library

Depend on the crate that owns the capability you need:

| Crate | Ownership and entry points |
|---|---|
| `packetcraftr-core` | `Packet`, protocol codecs/reflection, bounded documents, capture files, filters, the `conversation` builder, and `analysis::run` |
| `packetcraftr-netio` | Interface/route providers, capture/transmit resources, and platform backends |
| `packetcraftr` | `Client` preparation/send/exchange, route planning, neighbor resolution, `policy`, and DNS/replay/scan/traceroute/fuzz workflows |
| `packetcraftr-cli` | Arguments, composition, and rendering behind `packetcraftr_cli::main()`; its `output` module owns machine representations and the stream encoder |

Core is portable and independent of native I/O. A workflow uses one policy
implementation for operation admission and final-wire checks; target
resolution and replay frame admission add their specific boundaries. Offline analysis exposes a
physical `FrameRecord` with optional `TcpView` and `UdpView` observations.
Library callers run DNS with `client.dns(request, sink)`, whose TCP queries use
the client's `tcp` provider; the CLI composes
`packetcraftr_netio::tcp::SystemProvider`, which is available independently of
the native packet-I/O feature flags.

`Packet` accessors match concrete layer types: `get::<T>` returns the first
match while `iter_of::<T>` walks every match in packet order (double-ended, no
allocation), so `packet.iter_of::<Ipv4>().nth(1)` selects a later occurrence.
`iter_of_mut::<T>` edits all matches in place and, like the other mutable
accessors, clears cached encoded payload lengths when a match exists, even if
the iterator is dropped unconsumed; a no-match call leaves the cache intact.
`Frame::is_truncated()` reports capture metadata — the captured length is
below the declared original length — not whether protocol decoding succeeded
or is complete.

Runnable examples live in their owning crates and use only documentation
addresses and in-memory fixtures, so they need no native features or network
access:

```console
cargo run -p packetcraftr-core --example build_decode_filter
cargo run -p packetcraftr-core --example capture_analysis
cargo run -p packetcraftr --example client_composition --no-default-features
```

`client_composition` wires a `Client` over local route and recording-I/O
providers under an explicit `Policy` (destination allowlist plus finite
per-operation packet/byte limits) and shows both an admitted send and an
allowlist denial without emitting traffic. Browse the API with
`cargo doc --locked --workspace --all-features --no-deps --open`.

## Live networking

Live operations enforce destination policy, hostname-resolution opt-ins,
permissive-packet and source-spoofing controls, route/interface and MTU checks,
finite packet/byte/time budgets, and native OS permission requirements. Only
applicable commands expose each control; read that command's `--help` instead
of copying flags between workflows. See
[native validation](docs/native-validation.md) for how live capabilities are
validated, including in an isolated lab.

`--allow-destination ADDRESS[/PREFIX]` restricts live destinations to exact
addresses or canonical CIDR networks and may repeat. The list is checked at
target authorization, on every route-bearing address a packet declares, and
again on the destination the final wire bytes actually carry. Constraints only
narrow permission: a public destination inside the allowlist still needs
`--allow-public-destinations`. Network entries must spell the canonical network
address (`192.0.2.0/24`, not `192.0.2.1/24`); an absent list adds no
constraint.

Time budgets are checked at workflow boundaries and passed to native I/O where
its interface accepts a deadline. Event publication bounds the caller's wait.
Synchronous provider, reader, and resolver calls use their own I/O timeouts;
workflow checks cannot interrupt them or arbitrary injected callbacks. Timed-out
or cancelled workers retain their permits and resources until cleanup finishes.

| Platform | Requirements and notable limits |
| --- | --- |
| Linux | Layer 2 and raw Layer 3 usually require root or `CAP_NET_RAW`; complete builds need libpcap. Containers must expose the interface, route, and capability in the same namespace. |
| macOS | Layer 2 needs libpcap and BPF-device access; raw sockets usually require root. Complete-header raw IPv6 transmission is unsupported. |
| Windows | Layer 2 needs Npcap 1.88; raw sockets usually require administrator rights. Windows may reject raw UDP with a non-local source. |

These sample commands transmit or capture when run against reachable targets;
use them only on systems you are authorized to test. Each command's `--help`
lists its controls and limits:

```console
packetcraftr dns 192.0.2.53 example.test --type a
packetcraftr dns 127.0.0.1 example.test --tcp
packetcraftr scan 192.0.2.10 --transport tcp --ports 22,80,443
packetcraftr scan 192.0.2.10 --targets-file targets.txt --exclude-file skip.txt
printf '192.0.2.10\n192.0.2.11\n' | packetcraftr scan --targets-file -
packetcraftr scan --list 192.0.2.0/30 10.0.0.1 --output json
packetcraftr scan 192.0.2.0/28 --discovery only --discovery-probes icmp,neighbor
packetcraftr scan 192.0.2.10 --transport udp --ports 53,9000 \
  --udp-profiles examples/documents/udp-profiles.json --max-in-flight 8
packetcraftr replay capture.pcap --interface 2 --bps 8000000
packetcraftr replay capture.pcap --interface 2 --max-gap-ms 500
packetcraftr traceroute 192.0.2.1 --strategy icmp --payload-size 64 --dont-fragment --dscp 46
packetcraftr capture --interface 1 --write trace.pcapng --rotate-bytes 1048576 --rotate-files 4
```

- `dns` starts each attempt over UDP and continues over TCP once when a
  validated response is truncated, to the same reauthorized numeric server.
  `--udp-only` reports truncation as terminal, and `--tcp` queries directly over
  an ordinary TCP socket, which works in the portable profile without raw
  capture privileges. Several names plus repeatable `--reverse ADDRESS` form one
  bounded batch of at most 256 questions under one deadline.
- `scan` accepts IP addresses, hostnames, and CIDRs, bounded by `--max-targets`;
  hostname lookup needs the policy opt-in. `--connect` uses ordinary TCP
  sockets and works in the portable profile, while raw scans use
  `--max-in-flight` for a rolling response window. A `--udp-profiles` document
  selects per-port UDP requests and response checks; a matching profile is not
  authenticated service identity. `--discovery before|only|skip` adds a host
  discovery stage (ICMP echo, TCP, UDP, and ARP/NDP probes) under the same
  authorization and budgets, and publishes one host record per target with the
  evidence behind each response; silent hosts stay uncertain, not absent.
- `traceroute --payload-size`, `--dont-fragment` (IPv4 only), and `--dscp` shape
  the probes, `exchange --stop-when-answered` ends the response window once every
  request has a retained response, and `replay --max-gap-ms` clamps each
  captured gap after `--speed` scaling so idle periods do not stall a replay
  (it conflicts with `--rate`, `--bps`, and `--timing immediate`).
- `capture --capture-filter` is resolver-free native BPF applied before
  PacketcraftR queues and budgets frames, while `--filter` runs after capture.

## Contributing, security, and license

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidance. Report
suspected vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

PacketcraftR is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE). Bundled dependency
attributions are in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
