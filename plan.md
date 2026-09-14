# PacketcraftR implementation plan

Implement the 18 scoped improvements from the feature-gap assessment of
**2026-09-13** at `d96c16ca10480d1c9525ead0a964e646c6c76402`
(`0.5.0-beta.3` plus `[Unreleased]`). Original IDs, priorities, relative effort,
and exclusions are retained. This plan replaces the previous maintainability
plan. Feature status has not been revalidated and no implementation is marked
complete.

## Delivery approach

Before starting each item, inspect its current implementation and tests against
the assessment; adjust the remaining work to avoid duplicating existing behavior.
Deliver focused changes in the order below. Independent items can be scheduled
separately; the dependencies listed here are the intended integration order.
Effort estimates indicate relative size, not delivery commitments.

| Phase | Outcome | Items | Dependencies |
|---|---|---|---|
| 1 | Close high-priority build and probe workflows | BUILD-01, PROTO-02, LIVE-01 | Land PROTO-02 before integrating repeated ICMP probes |
| 2 | Expand bounded packet construction | BUILD-02, BUILD-03, PROTO-01, PROTO-03 | Independent of phase 1 except shared regression fixtures |
| 3 | Complete offline inspection and export | ANALYSIS-01, ANALYSIS-03, ANALYSIS-04, ANALYSIS-08 | Can use BUILD-01 fixtures; existing fixtures remain sufficient |
| 4 | Extend live policy and bounded operations | LIVE-13, LIVE-02, LIVE-08, LIVE-10 | BUILD-02 before LIVE-02; apply LIVE-13 constraints to all live paths |
| 5 | Ship documentation aids, examples, and arm64 archives | UX-01, LIB-01, DIST-01 | Finalize generated artifacts and examples after relevant APIs/CLI options settle |

Follow [AGENTS.md](AGENTS.md) and [CONTRIBUTING.md](CONTRIBUTING.md). Core owns
codecs, templates, capture formats, filters, and offline analysis; netio owns
provider contracts and native resources; the workflow crate owns policy,
budgets, preparation, and evidence; CLI owns composition and output contracts.
Keep native platform selection and unsafe code within their existing boundaries.
Reuse current codecs, collectors, writers, and pacing mechanisms where suitable.

Preserve wire values, malformed and unknown bytes, capture scope, and timestamp
precision. Validate untrusted input before allocating or expanding it. Live work
requires authorization before active discovery and final endpoint and wire
checks before every transmission, under finite operation budgets. Use typed
errors retaining original sources. Tests use fake providers, loopback,
documentation addresses, or isolated fixtures.

## Phase 1: High-priority workflow completion

### BUILD-01 — Save built packets as PCAP/PCAPNG

**Priority: high · Effort: small · Owner: CLI over core capture writer.**
Start with the [output contract](crates/packetcraftr-cli/src/output/contract.rs)
and existing capture-writing commands.

- [ ] Add build output selection for PCAP and PCAPNG using the existing writer.
  Support a single packet and expanded `--axis` sets without bypassing budgets.
- [ ] Require an explicit link type, validate it against the emitted packets,
  and specify deterministic default timestamps plus supplied timestamps.
- [ ] Integrate output options, errors, help, and examples with existing build
  rendering and file-output conventions.
- [ ] Verify both formats preserve bytes, link type, and supported timestamp
  precision. Test incompatible link types, limits, and output failures.

**Acceptance:** `read` consumes generated single-packet and axis captures;
`replay` consumes the same fixtures through fake or isolated providers without
an intermediate conversion or external traffic.

### PROTO-02 — Common ICMP/ICMPv6 body fields

**Priority: high · Effort: small–medium · Owner: core ICMP codecs.**
Start with the [ICMP codec](crates/packetcraftr-core/src/protocol/icmp.rs).

- [ ] Define typed echo identifiers/sequences and common error fields for
  ICMP/ICMPv6, including reported MTU, while retaining quoted and unknown bytes.
- [ ] Wire decoding, construction, reflection, filters, and projections to the
  same field definitions; preserve checksum behavior.
- [ ] Cover echo and error construction, exact byte round trips, filtering,
  projection, truncated bodies, and unknown types/codes.

**Acceptance:** supported body fields are constructible and queryable, and
quoted packets and unsupported bodies retain their original bytes. Exclude
nested quoted-packet decoding, stream correlation, and full NDP option typing.

### LIVE-01 — Bounded repeated probes with RTT statistics

**Priority: high · Effort: medium · Owner: workflow crate and CLI.**
Start with the [exchange model](crates/packetcraftr/src/exchange/model.rs).
Integrate ICMP field support from PROTO-02 and reuse portable TCP-connect.

- [ ] Add finite round counts and pacing under one policy budget and operation
  deadline; define how packet sets, rounds, and responses contribute to counts.
- [ ] Correlate repeated ICMP probes and collect portable TCP-connect outcomes.
  Specify duplicate/late-response handling and which samples contribute to RTT.
- [ ] Report sent, received, lost, and min/avg/max RTT, including no-response
  results and capture-loss caveats. Preserve individual evidence.
- [ ] Test pacing, accounting, timeouts, loss, cancellation cleanup, and denied
  operations with controlled providers; cover TCP-connect in the portable profile.

**Acceptance:** both probe paths run finite paced rounds, report consistent
counts and RTT statistics, and stop without further transmissions when budget,
deadline, or cancellation requires it. Additional transports and jitter
statistics remain out of scope.

## Phase 2: Packet construction and protocol fields

### BUILD-02 — Numeric ranges in template axes

**Priority: normal · Effort: small · Owner: core templates and CLI.**
Start with [templates](crates/packetcraftr-core/src/template.rs).

- [ ] Define inclusive numeric range syntax with an optional step and document
  direction, endpoint, signedness, and invalid-step behavior.
- [ ] Validate field types and calculate range and Cartesian-product sizes with
  checked arithmetic before generating packets; enforce the existing ceiling.
- [ ] Integrate range axes alongside explicit lists with deterministic ordering.

**Acceptance:** boundary and mixed-axis tests demonstrate correct expansion;
zero/invalid steps, incompatible fields, overflow, and over-limit sets fail
before materialization. Existing explicit-list behavior remains covered.

### BUILD-03 — Payload bytes from a file

**Priority: normal · Effort: small · Owner: CLI recipe loading.**
Use the existing [bytes expressions](crates/packetcraftr-core/src/expression.rs).

- [ ] Add an explicit CLI option identifying the file and destination bytes
  field; define conflicts with embedded values and reject non-bytes fields.
- [ ] Read within the existing input limit, including when a file grows or its
  reported size is unreliable. Enforce limits before unbounded allocation.
- [ ] Insert literal bytes into the resolved document so saved packet documents
  remain self-contained and core does not acquire filesystem-loading behavior.

**Acceptance:** empty and binary payloads build correctly; missing/unreadable
files, invalid fields, conflicts, and oversized input produce typed failures.
A saved document rebuilds after the source payload file is removed.

### PROTO-01 — Basic NTP decode and construction

**Priority: normal · Effort: medium · Owner: core application codecs.**
Start with [protocol registration](crates/packetcraftr-core/src/protocol/builtin/registry/registration.rs).

- [ ] Implement NTPv3/v4 client/server/broadcast headers and timestamps without
  losing their wire representation or fractional precision.
- [ ] Preserve extension fields and MAC bytes as bounded raw data; retain
  unsupported and malformed input through existing codec conventions.
- [ ] Register bindings and reflection, and expose construction of supported
  headers and timestamps.

**Acceptance:** valid version/mode fixtures construct and round-trip exactly;
reflection, truncated headers, malformed input, and retained trailing bytes
have coverage. NTP mode 6/7 control messages are excluded.

### PROTO-03 — Standard TCP option fields

**Priority: normal · Effort: medium · Owner: core TCP codec.**
Start with the [TCP codec](crates/packetcraftr-core/src/protocol/transport/tcp.rs).

- [ ] Type EOL/NOP, MSS, window scale, SACK-permitted/SACK, and timestamps while
  retaining option order, unknown bytes, and malformed encodings.
- [ ] Expose typed options to construction, filters, and projection. Derive
  option lengths and padding for newly constructed options within TCP limits.
- [ ] Keep decoding/re-encoding of existing bytes faithful instead of silently
  normalizing their padding or unsupported options.

**Acceptance:** tests cover each option, mixed order, unknown and malformed
options, exact round trips, construction limits, filtering, and projection.
IPv4 option expansion is excluded.

## Phase 3: Offline analysis and export

### ANALYSIS-01 — Compact capture summary

**Priority: normal · Effort: small · Owner: core stats and CLI.**
Start with the [stats report](crates/packetcraftr-core/src/analysis/stats/report.rs).

- [ ] Define duration, average packet size, and packet/byte rate calculations,
  including which byte counters they use and missing-time, empty-capture,
  zero-duration, and regressing-timestamp behavior.
- [ ] Add available interface, link-type, and snaplen metadata without inventing
  values for captures that do not provide them or collapsing distinct interfaces.
- [ ] Extend human and machine summaries and synchronize the output contract.

**Acceptance:** known PCAP/PCAPNG fixtures, multiple interfaces, absent metadata,
and degenerate time ranges yield documented, deterministic summaries. Hashing
and a full `capinfos` equivalent are excluded.

### ANALYSIS-03 — Surface existing non-TCP diagnostic evidence

**Priority: normal · Effort: small–medium · Owner: core expert analysis.**
Start with [expert findings](crates/packetcraftr-core/src/analysis/expert/).

- [ ] Route existing truncated-frame and clock-regression evidence from capture
  reads into expert findings without duplicating detection logic.
- [ ] Assign stable codes and severities and retain source-frame attribution
  and capture/interface context available from the reader.
- [ ] Cover positive, unaffected, and combined cases in analysis and CLI output.

**Acceptance:** both evidence types appear with stable identity and correct
frame attribution within existing finding limits. New TCP heuristics, ARP
anomalies, and DNS/HTTP collector integration are excluded.

### ANALYSIS-04 — Precise offline time bounds

**Priority: normal · Effort: small–medium · Owner: core time selection and CLI.**
Inspect [filter evaluation](crates/packetcraftr-core/src/filter/eval.rs) and the
shared offline selection path; existing `frame.time_epoch` floors to seconds.

- [ ] Add explicit start/stop epoch options with exact fractional-second parsing.
  Define both endpoints as inclusive and reject reversed bounds and unsupported
  precision rather than silently rounding.
- [ ] Compare bounds against capture timestamps using integer/rational precision,
  and document selection behavior for missing timestamps.
- [ ] Integrate selection with existing filters and budgets; count skipped frames
  toward read limits and do not assume timestamp ordering.

**Acceptance:** tests distinguish frames within one second and cover exact
endpoints, available capture resolutions, invalid bounds, out-of-order times,
and skipped-frame accounting. New filter date syntax and per-stream timing
metrics are excluded.

### ANALYSIS-08 — Save both followed directions

**Priority: normal · Effort: small · Owner: CLI follow.**
Start with the [follow command](crates/packetcraftr-cli/src/commands/follow/mod.rs).

- [ ] Add `follow --write` with deterministic per-direction filenames and
  documented behavior for empty directions and existing direction selection.
- [ ] Reuse output-byte limits across the operation. Stage output, publish files
  atomically without overwriting existing destinations, and define cleanup and
  reporting if publishing one direction fails.
- [ ] Test bidirectional byte fidelity, naming, limits, destination collisions,
  write failures, and cleanup without assuming a multi-file atomic transaction.

**Acceptance:** both directions can be saved in one invocation, existing files
remain intact, and failures never expose partially written individual files.

## Phase 4: Live policy and workflow extensions

### LIVE-13 — Explicit destination allowlists

**Priority: normal · Effort: medium · Owner: workflow policy and CLI.**
Start with the [policy model](crates/packetcraftr/src/policy/model.rs).

- [ ] Add exact IPv4/IPv6 address and CIDR constraints with documented matching
  and empty/absent-list semantics; retain existing authorization requirements.
- [ ] Enforce constraints at endpoint and final-wire boundaries, including
  prepared packets whose actual destination differs from the requested one.
- [ ] Record effective constraints and denials in evidence. Exercise the policy
  across existing live operations and the additions in LIVE-01/02/08.

**Acceptance:** exact, subnet-boundary, IPv4/IPv6, malformed-input, and final-wire
mismatch tests prove constraints narrow permission and cannot grant access
otherwise denied. Reusable policy files and general configuration are excluded.

### LIVE-02 — Send packet sets with repetition and pacing

**Priority: normal · Effort: small–medium · Owner: send workflow and CLI.**
Start with [send execution](crates/packetcraftr/src/send/execution.rs), reuse
BUILD-02 template expansion and existing pacing, and integrate LIVE-13 policy.

- [ ] Add axes, finite repetition, and a rate; define ordering and validate total
  expansion/repetition accounting with checked arithmetic before sending.
- [ ] Keep one packet/byte/time budget for the operation, with per-frame evidence
  and final endpoint and wire checks before every transmission.
- [ ] Preserve partial-progress evidence and cleanup on send failure, deadline,
  cancellation, and budget exhaustion.

**Acceptance:** controlled-provider tests verify ordering, repetition counts,
pacing, cumulative limits, per-frame checks, and stopping after a failure or
cancellation. No repeat option permits unbounded sending.

### LIVE-08 — Reverse DNS helper and bounded batches

**Priority: normal · Effort: small–medium · Owner: DNS workflow and CLI.**
Start with [DNS requests](crates/packetcraftr/src/dns/request.rs).

- [ ] Derive IPv4 `in-addr.arpa` and IPv6 `ip6.arpa` PTR question names from
  explicitly supplied addresses.
- [ ] Accept a bounded batch under one operation budget and deadline, retain
  explicit server selection, and report each question's outcome deterministically.
- [ ] Define partial-failure, cancellation, and unattempted-question reporting;
  retain existing transport behavior and apply destination constraints.

**Acceptance:** PTR fixtures cover both families; batch tests cover mixed
success/failure, size limits, shared budget/deadline exhaustion, and explicit
server use. EDNS expansion and system-resolver defaults are excluded.

### LIVE-10 — Decode frames while capturing

**Priority: normal · Effort: medium · Owner: CLI capture over core decoding.**
Start with [capture rendering](crates/packetcraftr-cli/src/commands/capture/rendering.rs).

- [ ] Add streaming decoded NDJSON through existing per-frame decoding and
  projection, retaining captured bytes and available capture metadata.
- [ ] Include frame diagnostics and enforce existing capture/output limits
  without accumulating an unbounded decoded result set.
- [ ] Integrate output failures and cancellation with capture cleanup and update
  the versioned machine-output contract and examples.

**Acceptance:** fake-capture fixtures exercise valid, truncated, and unknown
frames, projections, byte preservation, output exhaustion, and sink failure.
Live stream reassembly and application collectors are excluded.

## Phase 5: Tooling, examples, and distribution

### UX-01 — Generated shell completions and man pages

**Priority: normal · Effort: small · Owner: CLI and release packaging.**
Start with the [CLI manifest](crates/packetcraftr-cli/Cargo.toml) and clap definitions.

- [ ] Generate shell completions and man pages from the command definitions;
  document supported shells and the reproducible generation command.
- [ ] Package generated artifacts with release archives and extend the existing
  archive verifier to require the expected files.

**Acceptance:** generated documentation includes the finalized CLI options;
archive checks pass for complete packages and fail when required artifacts are
missing. Avoid maintaining a second handwritten command schema.

### LIB-01 — Runnable library examples

**Priority: normal · Effort: small · Owner: domain crates.**
Use [core contracts](crates/packetcraftr-core/tests/protocol_end_to_end_contracts.rs)
as starting patterns.

- [ ] Add compiled examples for offline build/decode/filter, capture analysis,
  and `Client` composition with explicit policy in their owning crates.
- [ ] Use self-contained fixtures or documentation addresses and clearly state
  invocation and feature requirements; avoid incidental live network effects.
- [ ] Build examples in CI under their supported profiles and run offline
  examples against isolated fixtures.

**Acceptance:** documented commands compile and offline examples run as shown;
`Client` composition demonstrates explicit authorization and finite budgets.

### DIST-01 — Linux arm64 release archives

**Priority: normal · Effort: small–medium · Owner: release workflow.**
Start with the [release matrix](.github/workflows/release.yml).

- [ ] Add `aarch64-unknown-linux-gnu` for both existing release variants with the
  required target toolchain and native dependencies.
- [ ] Apply existing smoke checks, linkage checks, archive verification,
  checksums, and attestations to the new artifacts, including UX-01 assets.
- [ ] Run smoke checks on a suitable arm64 runner or an explicitly configured
  execution environment; record execution evidence rather than compilation alone.

**Acceptance:** both arm64 variants produce verified archives and provenance
with the same release guarantees as existing targets. Installer integrations
remain separate.

## Validation and completion

For each implementation item, put unit tests beside the domain owner and public
behavior regressions in `crates/*/tests/`. Test observable behavior and meaningful
boundary failures, preserving the existing integration-test layout. Run affected
crate tests and applicable feature profiles using the pinned toolchain:

```sh
cargo test --locked -p <affected-crate>
cargo test --locked -p <affected-crate> --test <relevant-test>
```

Use the exact portable and pcap-free commands in
[CI](.github/workflows/ci.yml) when affected. Native/provider changes require
appropriate fake-provider and isolated runtime coverage; record unavailable
platform checks explicitly. Packaging changes require the existing archive
verifier and relevant release smoke checks. Build library examples in the
profiles they support. Run `cargo deny --locked check` when dependencies change.

Before integrating broad changes, run the comprehensive Linux checks with
`libpcap-dev` installed:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
```

An item is complete when its acceptance criteria and relevant checks pass,
help and examples reflect the behavior, and any changed machine contract has
synchronized schemas, CLI tests, and release assets with appropriate versioning.
Document user-visible and breaking changes in `[Unreleased]`. Use focused
Conventional Commits, record exact validation results and limitations in PRs,
and request applicable CODEOWNERS review. This planning edit does not claim
that implementation tests or native backends have been exercised.

## Scope boundaries

Do not expand this plan into specialized protocol families, alternate native
capture engines, advanced scan modes, path-MTU discovery, zone transfers, broad
capture transforms, pseudonymization, or general configuration without a
concrete user workflow and separate scope decision.

Existing exclusions remain: TLS decryption, HTTP/2/3 engines, DNSSEC validation,
wireless/line-rate/remote capture engines, service-fingerprint databases, hidden
resolution, unbounded live operations, and policy bypasses. Item-specific
exclusions above are part of acceptance. Consult [README](README.md) for
implemented capabilities and [CHANGELOG](CHANGELOG.md) for completed work.
