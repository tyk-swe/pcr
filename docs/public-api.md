# Public API and compatibility policy

PacketcraftR is a beta protocol-engineering toolkit. Public signatures are
reviewed release contracts, not permission to bypass the documented boundary
checks. Wire models remain deliberately accessible. Existing public APIs are
preserved by this hardening work; the earlier DNS/output changes in
[migration-unreleased.md](migration-unreleased.md) remain independently breaking.

| Crate | Supported surface | Private assembly |
| --- | --- | --- |
| `packetcraftr-core` | `Packet`, protocol/layer models (including raw, malformed and unknown values), reflection macros, `LayerCodec`, registry builder/bindings, build/decode contexts, bounded documents, capture readers/writers, filters, offline collectors and reassembly limits/events | Parser staging, payload pages, history rings, bookkeeping and codec registration assembly |
| `packetcraftr-netio` | Route/interface/neighbor/capture/transmit/TCP contracts and system adapters, typed errors, resource snapshots | Platform dispatch, native handles, permit pools, worker and reaper implementation |
| `packetcraftr` | `Client`, policies, preparation/execution entry points, finite workflow budgets, events/evidence, progress runtimes and cancellation | Materialization assembly and shared probe lifecycle implementation |
| `packetcraftr-cli` | Versioned machine envelopes, output models, stream encoding and optional resource metadata | Argument parsing, native provider composition and terminal rendering |

Protocol fields, unknown wire codes, provider traits, codec contexts and emitted
events are intentional extension points. Consumers must honor documented
non-exhaustive enums and distinguish raw bytes from decoded interpretation.
New native snapshot types are non-exhaustive; existing constructible types are
not retroactively made opaque or non-exhaustive.

Rust API changes, `packetcraftr.packet/v1`, and `packetcraftr.output/v3` have
separate compatibility decisions. An optional output field is additive for
consumers that accept unknown fields, but an older strict schema can reject it.
Resource metadata therefore requires explicit CLI opt-in; ordinary v3 records
remain unchanged. Schema validation alone does not prove stream completeness.
Consumers must check contiguous sequences and a terminal completion/error.

## Gates and release evidence

CI builds documentation with warnings denied for portable, pcap-free and
full-native profiles. `scripts/check-architecture.py` checks Cargo dependency
direction, including optional and target-specific production dependencies.
`compatibility/` is an independent Cargo workspace with its own lockfile and
real downstream codec, provider, offline collector and output-consumer tests.
Update its path dependency versions when bumping the workspace version.

`python3 scripts/check-public-api.py` generates four current and baseline
signature snapshots plus `API-DIFF.txt` and provenance. It compares the preceding
release tag by default; `--baseline REV` selects another baseline without
checking out over local work. Install `cargo-public-api` 0.52.0 and
`nightly-2026-08-28` to reproduce it. This nightly is an inspection dependency;
the supported build toolchain stays pinned in `rust-toolchain.toml`/`Cargo.toml`.
No older MSRV is promised.

API diffs include auto-trait and derived implementations, but omit blanket
implementations to reduce noise. Review removed/changed signatures against
migration notes; generated diffs do not prove behavioral compatibility. Release
preflight requires successful exact-commit API, decoder and Linux native evidence.
It publishes the API diff/current snapshots and `VALIDATION-EVIDENCE.json` with
checksums. Expired artifacts require rerunning that commit's qualifying CI run.
