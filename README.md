# PacketcraftR

PacketcraftR is one Rust library and command-line program for exact packet construction, bounded dissection, capture, replay, scanning, traceroute, DNS work, and field-aware fuzzing. It is designed for network and security professionals who need reproducible bytes, policy checks before transmission, and structured evidence without a daemon, account, database, telemetry, or persistent command history.

Version 0.3 replaces the structured-output contract with `packetcraftr.output/v2`. Packet documents remain `packetcraftr.packet/v1`.

## Safety and authorization

Use PacketcraftR only on systems and networks you own or are explicitly authorized to test. Live operations can transmit malformed traffic and, by default, capture in promiscuous mode without a filter. The CLI warns about that broad capture scope and about unthrottled multi-packet operations, but expert-oriented defaults remain unchanged.

Every active workflow retains finite packet, byte, frame-size, and duration limits. Omitting `--rate` means no additional rate ceiling; it does not disable those hard budgets. Prefer `--capture-mode host-only`, `--auto-filter` or `--capture-filter`, `--discard-unmatched`, and an explicit `--rate` when the broader defaults are unnecessary.

## Install

Release archives contain the binary, this README, the AGPL license, third-party notices, both schemas, a target-specific CycloneDX SBOM, and checksums. Linux artifacts target x86-64 with a glibc 2.35 baseline. macOS artifacts cover Intel and Apple Silicon. Windows x86-64 live Layer 2 operation requires the Npcap 1.88 runtime; offline and passive commands do not.

Linux live networking is the qualified 0.3 path. macOS and Windows live networking is labeled preview until privileged runners qualify it; their offline and passive behavior remains supported.

From crates.io:

```console
cargo install packetcraftr --locked
```

From source with the default full-native profile:

```console
cargo build --release --locked
```

For a portable offline/passive library build:

```console
cargo build --no-default-features --locked
```

The minimum supported Rust version is 1.96. Native Linux and macOS builds require libpcap development files at build time. Windows loads Npcap at runtime.

## First checks

`doctor` is passive unless `--probe-capture` is supplied:

```console
packetcraftr doctor
packetcraftr --output json doctor --interface eth0 --require interfaces,routes,layer2,layer3
packetcraftr doctor --interface eth0 --probe-capture --require capture
```

The capture probe opens a non-promiscuous `ip or ip6` filtered capture, waits for readiness, and closes it. It does not retain captured traffic or transmit a packet.

Offline examples:

```console
packetcraftr --output hex build --packet 'raw(bytes=hex:deadbeef)'
packetcraftr --output json dissect --hex deadbeef --link-type 147
packetcraftr --output ndjson read traffic.pcapng
```

Run `packetcraftr COMMAND --help` for command-specific budgets and policy flags.

## Structured output

Aggregate JSON contains the schema identifier, tool version and build target, operation ID, command, effective request, status, result or classified error, diagnostics, completion reason, and optional statistics. All sequences, seeds, timestamps, byte counters, offsets, and other 64-bit/platform-sized values are decimal strings.

NDJSON is incremental and flushes each record. It emits one `start` record immediately, zero or more item records as work completes, and exactly one terminal `complete`, `error`, or `cancelled` record. A late failure does not invalidate earlier records. Supply `--operation-id 0123456789abcdef0123456789abcdef` for reproducible correlation; otherwise PacketcraftR obtains 128 bits from operating-system entropy before active side effects.

Schemas are in [`schemas/packetcraftr.packet.v1.schema.json`](schemas/packetcraftr.packet.v1.schema.json) and [`schemas/packetcraftr.output.v2.schema.json`](schemas/packetcraftr.output.v2.schema.json). See [`docs/migration-output-v1-v2.md`](docs/migration-output-v1-v2.md) for the breaking migration.

## Evidence and cancellation

Aggregate exact capture evidence defaults to 16 MiB and is capped at 256 MiB with `--max-evidence-bytes`. Once the independent retention budget is exhausted, classifications, metadata, counters, and diagnostics continue where the workflow permits; diagnostics state `evidence_complete=false`. Use NDJSON, PCAP, or PCAPNG for exhaustive per-frame evidence. Human rendering previews at most 128 bytes and reports the complete length.

Replay is two-pass by default: PacketcraftR validates the complete file, timing, interface and mode, destinations, authorization policy, and aggregate budgets before the first delay or send. It then rewinds the same handle and verifies frame identity during execution. The library exposes `replay_streaming` only for non-seekable callers that explicitly accept partial-execution risk.

SIGINT and SIGTERM cancel waits, rate delays, and workflow batches. PacketcraftR stops new sends, shuts down and joins capture work, and emits terminal cancellation output. Exit status is 130 for SIGINT and 143 for SIGTERM unless cleanup cannot be confirmed, in which case the cleanup failure takes precedence.

## Documentation

- [`docs/operator-library-manual.md`](docs/operator-library-manual.md) — commands, privileges, output, library APIs, and troubleshooting
- [`docs/migration-output-v1-v2.md`](docs/migration-output-v1-v2.md) — structured-output migration
- [`docs/RELEASING.md`](docs/RELEASING.md) — artifact and qualification procedure
- [`SECURITY.md`](SECURITY.md) — vulnerability reporting and supported releases
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — development and review requirements

PacketcraftR is AGPL-3.0-only. It contains no telemetry and does not contact a PacketcraftR service.
