# Reviewed backlog

| Context | Decision |
|---|---|
| Baseline | `a71795a1` (`0.5.0-beta.3`); implementation started; progress and validation recorded in PLAN.md |
| Review | 7 raised → 7 kept; 0 merges. Four exploration lenses; three independent per-ID reviews |
| Split | I04: 2 KEEP / 1 DROP; main confirmed opaque-only core DNS records and required actual offline inspection, addressing the speculative-extraction objection |
| Sizing | S = local change; M = coordinated change; L = cross-layer change. Impact 1–3, higher is better |
| Dependencies | Implementation prerequisites; tiers use longest dependency depth. Shared-file scheduling is separate in PLAN.md |
| Priority | Impact/effort heuristic S=1, M=3, L=8: I07, I03, then I06 (tied with other M/2 tasks; deletion breaks tie) |

## Tier 0 — no dependencies

| ID | Title | Scope | Acceptance criteria | Effort | Impact | deps | Evidence |
|---|---|---|---|---|---|---|---|
| I03 | Compose DNS TCP fallback explicitly with network providers | Explicit DNS TCP transport composition; native socket ownership in netio; workflow framing/policy/evidence and CLI assembly. | Injected UDP/client fixtures cannot silently select system TCP; TCP provider is explicit and replaceable. Native sockets/resources belong to netio; DNS framing/validation stays domain-owned. Preserve endpoint reauthorization, final query checks, route-override rejection, finite connect/write/read budget, cancellation and exact evidence. Remove the unconditional executor/system-socket path. | M | 3 | [] | `crates/packetcraftr/src/dns/executor.rs:104`; `crates/packetcraftr/src/dns/tcp.rs:309`; `crates/packetcraftr/src/dns/tcp.rs:350`; `crates/packetcraftr-cli/src/commands/execution.rs:72` |
| I04 | Expose bounded DNS record decoding in offline inspection | Extract bounded neutral DNS records/types into core and consume them in existing offline DNS dissection/reflection; reuse that parser in live DNS. | Offline read/dissect exposes supported answer/authority/additional records and EDNS plus exact unknown RDATA. Core stays independent of workflows/netio; original wire remains round-trippable. Malformed/truncated records and all byte/record/name/TXT limits produce bounded diagnostics or typed failures without invented values. Live expected-query/relevance checks remain in workflows. Remove duplicate decoding and synchronize affected machine contracts, examples and migration documentation. | L | 2 | [] | `crates/packetcraftr-core/src/protocol/application/dns.rs:57`; `crates/packetcraftr-core/src/protocol/application/dns.rs:106`; `crates/packetcraftr/src/dns/report.rs:31`; `crates/packetcraftr/src/dns/wire/decode.rs:76` |
| I05 | Preserve typed validation causes in netio | Netio interface-validation and route-semantics error conversion paths and owned error definitions/tests. | Error::source() retains actual validation/semantic causes, including through the real conversion helpers; existing classification codes remain stable. Source chains avoid duplicate messages; locally constructed route failures still work without an invented source. Document any changed public error fields. | M | 2 | [] | `crates/packetcraftr-netio/src/platform/dispatch.rs:103`; `crates/packetcraftr-netio/src/route/planner.rs:92`; `crates/packetcraftr-netio/src/route/error.rs:85`; `crates/packetcraftr-netio/tests/error_contracts.rs:38` |
| I06 | Consolidate release archive smoke checks | One standard-library Python archive verifier replacing duplicate Unix/Windows assertion blocks; retain extraction/runtime checks. | Both archive paths invoke the same verifier for required nonempty files, build identity, version, exact build/dissect bytes, NDJSON sequence/schema/completion and packaged examples. Fail on missing assets, nonzero commands, corrupt identity or malformed output. Delete duplicate checks; retain Unix executable checks, Windows extraction and Linux clean-runtime/linkage checks. | M | 2 | [] | `.github/workflows/release.yml:269`; `.github/workflows/release.yml:285`; `.github/workflows/release.yml:327`; `.github/workflows/release.yml:332`; `.github/workflows/release.yml:369` |
| I07 | Truncate completed stats tables directly | Only stats cap_table ownership/omitted-row calculation; retain shared Retained for its other consumers. | Compute omitted count from original vector length and truncate in place; preserve table order, diagnostics, text/JSON parity and fragment-table exception for absent, zero, below/equal/above-length limits. Existing offline workflow tests pass; no new abstraction. | S | 1 | [] | `crates/packetcraftr-cli/src/commands/stats/mod.rs:72`; `crates/packetcraftr-cli/src/commands/stats/mod.rs:78` |

## Tier 1 — after shared DNS decoding

| ID | Title | Scope | Acceptance criteria | Effort | Impact | deps | Evidence |
|---|---|---|---|---|---|---|---|
| I01 | Accept numeric DNS query types | Workflow DNS request/wire matching; CLI DNS parsing and output; schemas, examples, release contract references and migration docs. | Accept bounded numeric QTYPE syntax and existing aliases; encode and match exact codes; preserve unknown RDATA; reject malformed/out-of-range input before I/O. Migrate the strict output contract to a new version and synchronize every producer, schema, example, release smoke and consumer test; document API/output changes. | M | 2 | [I04] | `crates/packetcraftr-cli/src/commands/dns/arguments.rs:18`; `crates/packetcraftr/src/dns/request.rs:24`; `crates/packetcraftr/src/dns/wire/encode.rs:37`; `crates/packetcraftr/src/dns/report.rs:189`; `schemas/packetcraftr.output.v2.schema.json:5422` |
| I02 | Add bounded opt-in EDNS request settings | DNS request settings, query encoding, budget accounting, CLI flags and existing DNS regressions. | Default query bytes stay identical; opt-in EDNS v0 emits exactly one valid OPT with bounded payload size and DO bit. Validate settings before I/O; account for all added bytes; UDP and TCP send the same query within existing authorization, retry and shared-deadline rules. Document that DO requests data, not DNSSEC validation. | M | 2 | [I04] | `crates/packetcraftr/src/dns/wire/encode.rs:13`; `crates/packetcraftr/src/dns/wire/encode.rs:35`; `crates/packetcraftr/src/dns/report.rs:137`; `crates/packetcraftr-cli/src/commands/dns/arguments.rs:74` |

## Execution constraints

| Area | Requirement |
|---|---|
| Architecture | Follow AGENTS.md; core independent of native I/O/workflows; unsafe only in netio platform with specific SAFETY invariants; expose capabilities, keep assembly private |
| Contracts | Changed machine contracts require a new version; keep packet/output versioning independent and synchronize schemas, examples, tests, release assets and migrations. Do not silently widen output-v2 enums |
| Evidence and live I/O | Preserve malformed/unknown bytes, capture scope/timestamps, finite budgets, authorization before discovery and final endpoint/byte checks; fixtures, loopback or documentation addresses only |
| Delivery | Future branches `tyk/<task>`; focused Conventional Commits; user-visible/breaking changes in `[Unreleased]`; exact validation results and applicable CODEOWNERS review |
