# Changelog

All notable changes are documented here. PacketcraftR follows semantic versioning from 0.3 onward.

## 0.3.0

### Breaking

- Replaced `packetcraftr.output/v1` with immutable `packetcraftr.output/v2`; packet documents remain v1.
- Changed NDJSON to an explicit incremental start/item/terminal lifecycle.
- Changed 64-bit and platform-sized structured values to decimal strings and durations to explicit second/nanosecond objects.
- Made two-pass `prepare` plus `execute` the normal replay library contract; retained explicit `replay_streaming` for non-seekable inputs.

### Added

- Added `doctor`, passive readiness reporting, an opt-in zero-transmission capture probe, and required-capability checks.
- Added 128-bit operation IDs, stable domain-separated derived packet identifiers, OS source-port reservation, shared cancellation, completion reasons, and event sinks.
- Added capture mode, automatic/custom BPF, unmatched-evidence discard, evidence budgets, and structured broad-capture/unthrottled warnings.
- Added streaming exchange, scan, traceroute, DNS, fuzz, and replay evidence APIs.
- Added the default `native` feature aggregating route, Layer 2, and Layer 3 support.

### Hardened

- Capture mode and filters are configured before readiness and transmission.
- Replay validates the complete seekable input before delay or send and verifies frame identity on its execution pass.
- SIGINT/SIGTERM cancellation stops new sends, interrupts bounded waits, and requires confirmed capture cleanup.
- Exact frame bytes are retained once; hexadecimal is lazy, aggregate evidence is bounded, JSON writes directly to locked stdout, and human previews are bounded.
- Batched probes use lockstep correlation fields so IP and transport identifiers remain unique per generated probe.

## 0.2.0

- Established the single-crate PacketcraftR packet, capture, native networking, and workflow baseline.
