# Refactor parity

This document fixes the compatibility oracle for the behavior-preserving
modernization program. Characterization began at commit
`87ad5755acccfa5aff304f5fbb0ee59bf2492649` (`87ad575`). Before publication,
`main` advanced through
`d957a5ebef2cc4fa7ad7c06e019b61183b16d2ab` (`d957a5e`), including the
intentional analysis/budget crate split and stricter lint policy. The rebased
refactor's integration baseline is therefore `d957a5e`; its existing results
are authoritative and must not be rebaselined by this refactor.

## Contract boundary

The workspace consists of the following independently consumable crates:

- `packetcraftr-error`: shared classified errors;
- `packetcraftr-budget`: checked deadline and finite-budget primitives;
- `packetcraftr-capture`: bounded classic PCAP and PCAPNG I/O;
- `packetcraftr-session`: bounded IP-fragment and TCP reassembly;
- `packetcraftr-packet`: packet models, registries, building, and dissection;
- `packetcraftr-protocol`: built-in codecs and the support manifest;
- `packetcraftr-net`: provider interfaces and all native I/O;
- `packetcraftr-client`: policy-gated send and exchange operations;
- `packetcraftr-analysis`: bounded offline capture analysis;
- `packetcraftr-workflow`: active workflows;
- `packetcraftr-output`: render-neutral output models; and
- `packetcraftr`: the facade, which reexports ten domain crates under
  their canonical module names.

The `packetcraftr-cli` binary consumes the facade. Refactors must preserve crate
names, public paths and reexports, public types and trait methods, and the
acyclic dependency direction. They must not move `unsafe` code outside
`packetcraftr-net/src/platform/`.

Public compatibility defaults, including default trait methods, remain part of
the API. The authoritative built-in protocol and workflow topology is
`packetcraftr_protocol::support::BUILTIN_PROTOCOL_SUPPORT`; registration order,
aliases, fallback behavior, and external protocol composition are contracts.

## Observable contracts

The following artifacts and behavior form the parity oracle:

- The complete CLI help, option ordering, parse behavior, exit codes, stdout
  and stderr routing, text rendering, JSON envelopes, and NDJSON sequences.
- `schemas/packetcraftr.packet.v1.schema.json`,
  `schemas/packetcraftr.output.v1.schema.json`, every committed document under
  `examples/documents/`, and CLI goldens under
  `crates/packetcraftr-cli/tests/golden/`.
- Exact packet bytes, layer order, offsets, padding, checksum behavior,
  binding validation, bounded fallback behavior, and deterministic traversal.
- Classic PCAP and PCAPNG byte order, timestamps, snapshot lengths, link types,
  section and interface metadata, allocation bounds, terminal errors, and
  fail-atomic reader state.
- Fragment and TCP reassembly serial arithmetic, overlap policy, quotas,
  expiry, eviction order, and plan-then-commit fail-atomicity.
- Workflow validation and error precedence, authorization before live side
  effects, checked packet/byte/statistics accounting, finite evidence and time
  budgets, deadline-check positions, diagnostic deduplication, candidate
  ranking, and deterministic output ordering.
- Native provider feature dispatch, error classification, route ranking and
  source/interface selection, capture queue policy, timestamp conversion,
  namespace invalidation, handle ownership, and panic propagation.

Filtered capture copies must remain streaming. PCAPNG copies preserve source
interface descriptions; output paths that synthesize interfaces continue to
map them by link type. Converting metadata that classic PCAP cannot represent
must continue to fail before emitting output.

## Native feature matrix

The facade and CLI expose the same four feature names as `packetcraftr-net`:

| Feature | Dependency | Contract |
| --- | --- | --- |
| `native-interfaces` | none | Native interface enumeration |
| `native-route` | `native-interfaces` | Native route lookup |
| `native-layer2` | `native-interfaces` | Native link-layer capture/transmit |
| `native-layer3` | `native-interfaces` | Native raw-IP transmit |

The default feature set is exactly `native-interfaces`. Portable
`--no-default-features`, default, and `--all-features` profiles are supported.
The release pcap-free profile is
`--no-default-features --features native-route,native-layer3`; it must not link
libpcap or Npcap. Unsupported OS/feature combinations retain their classified
errors. Linux, macOS Intel and Arm, Windows MSVC, and the configured FreeBSD
compile checks remain release gates.

## Refactor-pass oracles

Each pass uses the narrow owning tests first and the common gates below. Its
additional oracle is:

1. **Parity baseline:** this document, public rustdoc, schemas, examples,
   goldens, external-consumer tests, and the six fuzz targets.
2. **CLI test topology:** identical `cargo test -p packetcraftr-cli -- --list`
   test names and counts, plus all CLI integration suites.
3. **Large test splits:** identical owning-crate test names, counts, and
   assertions.
4. **Offline CLI preparation:** complete-help golden and stats, expert, and
   follow fixtures; precedence among invalid format, selector, direction,
   limits, filter, interval, missing input, and malformed capture.
5. **Capture output:** PCAP/PCAPNG round trips, empty filtered output,
   multi-interface preservation, metadata-loss rejection, custom bounds,
   timestamps, link types, stdout failures, replay evidence, and capture
   goldens.
6. **Evidence split:** exact error text and precedence, diagnostic
   deduplication, response ordering, timeouts, and checked statistics in DNS,
   scan, traceroute, replay, and fuzz.
7. **Probe runner:** controlled-provider scan and traceroute suites, including
   validation/authorization order, deadlines, pacing, terminal-hop stopping,
   accounting, and error mapping.
8. **DNS wire modules:** all DNS wire, record, correlation, outcome, malformed,
   bounded-input, and exact-selection tests plus `dns_wire`.
9. **Expert state machine:** the full expert matrix and CLI expert, follow, and
   stats fixtures, including eviction, sequence wrap, gaps, probes, duplicate
   ACKs, zero windows, FIN/RST, trailing events, and finding order/severity.
10. **Protocol registration:** manifest consistency, conflicts, all protocol
    round trips, corpus rebuilds, aliases, and external composition.
11. **Packet engines:** build/decode tests, protocol round trips,
    documents/schemas, fixtures, external providers, `decode_roundtrip`, and
    `packet_inputs`.
12. **PCAPNG reader:** malformed/truncated data, bounds, sections, timestamps,
    poisoning/atomicity, transcode, truncation corpus, and `capture_reader`.
13. **Reassembly:** session and facade properties, expiry, independent flows,
    rejection rollback, quotas, serial wrap, and `reassembly_state`.
14. **Route policy:** route planning on every CI OS, all feature profiles,
    unsupported-feature errors, preferred source/interface hints, and FreeBSD
    compilation.
15. **Live capture:** lifecycle, wakeup, shutdown, overflow policy, checked drop
    counters, timestamps, panic/error propagation, and Linux namespace E2E.
16. **Raw IP:** IPv4/IPv6 validation, checksums, error mapping, pcap-free
    release, feature powerset, platform CI, and Linux native E2E.
17. **Linux netlink:** all-feature and pcap-free tests,
    namespace-switch/worker-failure cases, and IPv4/IPv6 namespace E2E.
18. **macOS:** Intel and Arm feature profiles, pure route-parser tests, Clippy,
    and both release variants.
19. **Windows/Npcap:** all feature profiles, malformed/bounded parser tests,
    DLL discovery/error mapping, pcap-free linkage, all-feature release, and
    review of `unsafe` confinement and adjacent `SAFETY` explanations.
20. **Closeout:** the complete gate below, 78% coverage, six deterministic fuzz
    smokes, documentation/schema/example/golden validation, authorized Linux
    native E2E, and a clean tracked baseline plus the intended refactor diff.

## Common validation gate

Run the narrow tests after each pass. Before closeout, run:

```console
cargo test --locked --no-default-features
cargo test --locked
cargo test --locked --all-features
cargo check --locked --release --package packetcraftr-cli \
  --no-default-features --features native-route,native-layer3
cargo clippy --locked --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --all-features --no-deps
cargo fmt --all -- --check
scripts/check-source-conventions
```

CI additionally checks Rust 1.96, the pairwise feature powerset, configured
platform targets, dependency policy, 78% line coverage, deterministic
1,000-run fuzz smokes for all six targets, and the authorized Linux native
namespace harness.

## Closeout audit

The rebased refactor was compared directly with `d957a5e`:

- Generated public-API listings are identical for all twelve library crates
  under portable, default, and all-feature profiles. The facade's ten canonical
  reexports are unchanged.
- Root help, version output, and help for all 18 CLI commands are
  byte-identical. Schemas, examples, fixtures, goldens, manifests, lockfiles,
  feature declarations, and the normalized dependency graph are unchanged.
- Every added Rust source is reachable from an owning module. Warning-free
  portable, default, all-feature, MSRV, feature-powerset, and target checks
  found no new private dead code. `unsafe` blocks, functions, and
  implementations remain confined to `packetcraftr-net/src/platform/`.
- The largest mechanically split tests fell from 3,198 to 1,713 lines
  (offline analysis), 1,353 to 415 lines (PCAP), and 2,464 to 755 lines
  (protocol round trips). Production hotspots fell from 950 to 470 lines
  (evidence), 929 to 450 (DNS wire), 1,133 to 582 (live capture), 769 to 351
  (raw IP), 757 to 301 (Linux netlink), and 793 to 236 (Npcap).
- The duplication audit found one owner each for offline analysis preparation,
  capture-output interface lifecycles, probe execution, route finalization,
  fragment planning, PCAPNG option parsing, and DNS name canonicalization.
  Only superseded private helpers made unreachable by those consolidations
  were deleted.

The closeout validation achieved 81.12% line coverage, completed 1,000
deterministic runs for each of the six fuzz targets, and passed all seven
authorized Linux namespace cases with complete topology cleanup.

The session crate's `packetcraftr-packet` and `packetcraftr-protocol`
development dependencies are intentional: its module-level doctest adapts
decoded protocol layers into reassembly inputs. Native cfg dispatch is likewise
intentional and must not be removed or suppressed as unused code.
