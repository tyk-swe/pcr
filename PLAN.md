# Parallel execution plan

| Context | Rule |
|---|---|
| Status | Implementation in progress on `tyk/implement-backlog`; see execution log below |
| Baseline | `a71795a1`; re-read AGENTS.md and revalidate evidence if the branch advances |
| Capacity | One coordinator plus at most three concurrent agents; one implementation agent per task |
| Isolation | Use isolated worktrees on `tyk/<task>` branches; integrate completed tasks before the next wave |
| Coordination | DNS tasks share parser/request/executor/contract tests, so serialize them. I01/I02 depend on I04; other sequencing avoids shared-file conflicts, not artificial dependencies |
| Shared files | Coordinator integrates CHANGELOG.md/docs and schema-version references in release checks; integrate I06's shared checker before applying I04's contract references. Never let concurrent agents overwrite shared files |
| Contract migrations | I04 decides affected packet/output contracts; I01 must migrate the strict DNS query-type contract. Coordinate one pending unreleased migration where possible; independently version changed packet/output contracts and update all consumers |
| Scope | Prefer deleting superseded code; no general socket framework, parser framework, config matrix or duplicate public path |

## Gates and validation

| Gate | Required action |
|---|---|
| S task | No dedicated task review gate; still run its checks and wave cleanup |
| M task | One read-only `code-review` agent after implementation; resolve findings and rerun affected checks |
| L task | One read-only `code-review` agent, then a `debt-collector` agent removes task-created dead code/abstractions; rerun affected checks |
| Every wave, including 0 | One final `debt-collector` pass over touched files after integration; delete only proven dead/duplicate code; preserve intentional unavailable-provider stubs and boundary checks |
| Every wave exit | Relevant tests green, `cargo fmt --all -- --check` and `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` pass; no new lint. Run `cargo test --locked --workspace --all-features` on integrated changes. Linux requires libpcap-dev |
| Additional checks | If fuzz changes, format its manifest and run affected bounded targets; if feature/platform/release behavior changes, run the matching existing CI matrix checks. Record exact commands/results; unavailable checks are not passes and remain outstanding |
| Final delivery | No unresolved required checks/reviews; updated Unreleased/migrations/contracts; applicable CODEOWNERS review requested with PR. No release publishing is part of this plan |

## Wave 0 — finish partial work

| Entry | Task and self-contained prompt | Gates | Exit |
|---|---|---|---|
| Start from the recorded baseline or reviewed successor; preserve existing user changes | **finish-partials agent:** Read AGENTS.md and the manifests. Search with `rg -n -e TODO -e FIXME -e XXX -e stub -e 'not implemented' crates scripts fuzz .github`; inspect multiline empty functions, feature flags absent from profiles, unused exports and ignored/unused tests with `rg` plus callers/manifests/CI. Complete or remove only verified partial work before new tasks. Intentional fail-closed backend stubs, empty callbacks and public library exports are not evidence of unfinished work. Record no-op findings when nothing qualifies. Keep changes with their domain owner and retain byte fidelity, authorization, finite limits and unsafe boundaries. If cleanup overlaps a backlog item, complete and validate that item or leave it for its scheduled agent; update the plan without doing it twice. | Size each actual change using S/M/L gates above; final wave debt-collector pass, even if it reports no touched files | Partial work resolved or proven intentional; revalidate task evidence/dependencies; tests green and no new lint under the common exit gate |

## Waves 1–4

| Wave | Entry condition | Tasks in parallel | Task gates | Exit condition |
|---|---|---|---|---|
| 1 | Wave 0 gate passed; task evidence still valid | I04 offline DNS records; I05 typed netio errors; I06 shared release smokes | I04: code-review + task debt-collector; I05/I06: code-review each | All three accepted and integrated; one wave debt-collector; common exit gate and affected DNS/schema/fuzz/release checks |
| 2 | Wave 1 integrated; updated DNS type/module paths available | I03 explicit DNS TCP composition; I07 stats truncation | I03: code-review; I07: no dedicated task gate | Both accepted and integrated; one wave debt-collector; common exit gate plus relevant portable/native contracts |
| 3 | Wave 2 integrated; I04 prerequisite complete | I01 numeric DNS query types | code-review | Contract migration, producers/consumers/examples and archive verifier agree; one wave debt-collector; common exit gate |
| 4 | Wave 3 integrated; I04 prerequisite complete; DNS request representation settled | I02 bounded EDNS requests | code-review | Default bytes and opt-in behavior verified; one wave debt-collector; common exit gate and final delivery checks |

All eligible nonconflicting tasks run up to the three-agent limit. I03/I04/I01/I02 are serialized because their DNS modules, public types and regressions overlap; I07 fills the next available slot. Integration gates, rather than extra backlog prerequisites, enforce this ordering.

## Implementation agent prompts

### I01 — Accept numeric DNS query types

| Prompt component | Instruction |
|---|---|
| Task | Implement I01 only on `tyk/i01` after its wave entry gate. Read AGENTS.md; preserve user changes. Effort M; code-review required. |
| Files | crates/packetcraftr/src/dns/{request,wire,engine}.rs and wire/; crates/packetcraftr-cli/src/commands/dns/ and src/output/dns/; schemas/; examples/documents/; CLI contract tests; .github/workflows/release.yml; README.md; docs/; CHANGELOG.md |
| Evidence to verify | `crates/packetcraftr-cli/src/commands/dns/arguments.rs:18`; `crates/packetcraftr/src/dns/request.rs:24`; `crates/packetcraftr/src/dns/wire/encode.rs:37`; `crates/packetcraftr/src/dns/report.rs:189`; `schemas/packetcraftr.output.v2.schema.json:5422` |
| Scope and constraints | Workflow DNS request/wire matching; CLI DNS parsing and output; schemas, examples, release contract references and migration docs. Preserve exact bytes, scope/timestamps, finite input/resource budgets and original typed causes. Keep native resources in netio, workflow policy outside core, unsafe only in netio platform with SAFETY comments. Use fixtures/loopback/documentation addresses; retain authorization before discovery and final endpoint/byte checks. Delete superseded paths; add no general framework. |
| Done criteria | Accept bounded numeric QTYPE syntax and existing aliases; encode and match exact codes; preserve unknown RDATA; reject malformed/out-of-range input before I/O. Migrate the strict output contract to a new version and synchronize every producer, schema, example, release smoke and consumer test; document API/output changes. Add user-visible/breaking changes to Unreleased and keep affected schemas/examples/docs/release assets synchronized. |
| Verification and handoff | Run `cargo test --locked -p packetcraftr` and `cargo test --locked -p packetcraftr-cli --no-default-features`; include DNS wire/matching, aggregate/NDJSON schemas, published examples and updated release archive smoke checks. Run rustfmt and affected Clippy checks. Report changed files, exact check results, unresolved platform checks and any scope/size change; if effort grows to L, add both L gates. Do not publish, merge or execute other backlog tasks. |

### I02 — Add bounded opt-in EDNS request settings

| Prompt component | Instruction |
|---|---|
| Task | Implement I02 only on `tyk/i02` after its wave entry gate. Read AGENTS.md; preserve user changes. Effort M; code-review required. |
| Files | crates/packetcraftr/src/dns/{request,wire,engine,plan,probe,evidence}.rs and wire/encode.rs; crates/packetcraftr-cli/src/commands/dns/; crates/packetcraftr/tests/dns_*; crates/packetcraftr-cli/tests/dns_output_contracts.rs; README.md; CHANGELOG.md |
| Evidence to verify | `crates/packetcraftr/src/dns/wire/encode.rs:13`; `crates/packetcraftr/src/dns/wire/encode.rs:35`; `crates/packetcraftr/src/dns/report.rs:137`; `crates/packetcraftr-cli/src/commands/dns/arguments.rs:74` |
| Scope and constraints | DNS request settings, query encoding, budget accounting, CLI flags and existing DNS regressions. Preserve exact bytes, scope/timestamps, finite input/resource budgets and original typed causes. Keep native resources in netio, workflow policy outside core, unsafe only in netio platform with SAFETY comments. Use fixtures/loopback/documentation addresses; retain authorization before discovery and final endpoint/byte checks. Delete superseded paths; add no general framework. |
| Done criteria | Default query bytes stay identical; opt-in EDNS v0 emits exactly one valid OPT with bounded payload size and DO bit. Validate settings before I/O; account for all added bytes; UDP and TCP send the same query within existing authorization, retry and shared-deadline rules. Document that DO requests data, not DNSSEC validation. Add user-visible/breaking changes to Unreleased and keep affected schemas/examples/docs/release assets synchronized. |
| Verification and handoff | Run `cargo test --locked -p packetcraftr` and `cargo test --locked -p packetcraftr-cli --no-default-features`; cover exact default/OPT bytes, boundary values, rejection before I/O, truncation fallback, added-byte accounting and cancellation. Run rustfmt and affected Clippy checks. Report changed files, exact check results, unresolved platform checks and any scope/size change; if effort grows to L, add both L gates. Do not publish, merge or execute other backlog tasks. |

### I03 — Compose DNS TCP fallback explicitly with network providers

| Prompt component | Instruction |
|---|---|
| Task | Implement I03 only on `tyk/i03` after its wave entry gate. Read AGENTS.md; preserve user changes. Effort M; code-review required. |
| Files | crates/packetcraftr/src/dns/{executor,tcp,execution,engine}.rs; crates/packetcraftr-netio/src/ and src/platform/ as needed; crates/packetcraftr-cli/src/commands/execution.rs; crates/packetcraftr/tests/dns_tcp_contracts.rs and dns_cancellation_contracts.rs; README.md; CHANGELOG.md |
| Evidence to verify | `crates/packetcraftr/src/dns/executor.rs:104`; `crates/packetcraftr/src/dns/tcp.rs:309`; `crates/packetcraftr/src/dns/tcp.rs:350`; `crates/packetcraftr-cli/src/commands/execution.rs:72` |
| Scope and constraints | Explicit DNS TCP transport composition; native socket ownership in netio; workflow framing/policy/evidence and CLI assembly. Preserve exact bytes, scope/timestamps, finite input/resource budgets and original typed causes. Keep native resources in netio, workflow policy outside core, unsafe only in netio platform with SAFETY comments. Use fixtures/loopback/documentation addresses; retain authorization before discovery and final endpoint/byte checks. Delete superseded paths; add no general framework. |
| Done criteria | Injected UDP/client fixtures cannot silently select system TCP; TCP provider is explicit and replaceable. Native sockets/resources belong to netio; DNS framing/validation stays domain-owned. Preserve endpoint reauthorization, final query checks, route-override rejection, finite connect/write/read budget, cancellation and exact evidence. Remove the unconditional executor/system-socket path. Add user-visible/breaking changes to Unreleased and keep affected schemas/examples/docs/release assets synchronized. |
| Verification and handoff | Run `cargo test --locked -p packetcraftr-netio -p packetcraftr -p packetcraftr-cli --all-features` and their portable profile; include fake-provider fallback, connect/read/write timeout, endpoint mismatch, partial framing, route overrides and DNS cancellation. Run deterministic native contracts on supported CI platforms. Run rustfmt and affected Clippy checks. Report changed files, exact check results, unresolved platform checks and any scope/size change; if effort grows to L, add both L gates. Do not publish, merge or execute other backlog tasks. |

### I04 — Expose bounded DNS record decoding in offline inspection

| Prompt component | Instruction |
|---|---|
| Task | Implement I04 only on `tyk/i04` after its wave entry gate. Read AGENTS.md; preserve user changes. Effort L; code-review and task debt-collector required. |
| Files | crates/packetcraftr-core/src/protocol/application/dns.rs and owned DNS codec/reflection modules; crates/packetcraftr/src/dns/{report,request,wire}.rs and wire/decode/; crates/packetcraftr-cli/src/output/ and offline rendering as needed; core/workflow DNS tests; CLI offline and schema tests; fuzz/fuzz_targets/dns_message.rs; schemas/; examples/; README.md; docs/; CHANGELOG.md |
| Evidence to verify | `crates/packetcraftr-core/src/protocol/application/dns.rs:57`; `crates/packetcraftr-core/src/protocol/application/dns.rs:106`; `crates/packetcraftr/src/dns/report.rs:31`; `crates/packetcraftr/src/dns/wire/decode.rs:76` |
| Scope and constraints | Extract bounded neutral DNS records/types into core and consume them in existing offline DNS dissection/reflection; reuse that parser in live DNS. Preserve exact bytes, scope/timestamps, finite input/resource budgets and original typed causes. Keep native resources in netio, workflow policy outside core, unsafe only in netio platform with SAFETY comments. Use fixtures/loopback/documentation addresses; retain authorization before discovery and final endpoint/byte checks. Delete superseded paths; add no general framework. |
| Done criteria | Offline read/dissect exposes supported answer/authority/additional records and EDNS plus exact unknown RDATA. Core stays independent of workflows/netio; original wire remains round-trippable. Malformed/truncated records and all byte/record/name/TXT limits produce bounded diagnostics or typed failures without invented values. Live expected-query/relevance checks remain in workflows. Remove duplicate decoding and synchronize affected machine contracts, examples and migration documentation. Add user-visible/breaking changes to Unreleased and keep affected schemas/examples/docs/release assets synchronized. |
| Verification and handoff | Run `cargo test --locked -p packetcraftr-core -p packetcraftr -p packetcraftr-cli --no-default-features`; cover offline captured response records, unknown/malformed/truncated RDATA, exact wire round trips, each parser limit, and unchanged live response relevance. Run affected schema/examples and a bounded DNS fuzz smoke using CONTRIBUTING.md. Run rustfmt and affected Clippy checks. Report changed files, exact check results, unresolved platform checks and any scope/size change; if effort grows to L, add both L gates. Do not publish, merge or execute other backlog tasks. |

### I05 — Preserve typed validation causes in netio

| Prompt component | Instruction |
|---|---|
| Task | Implement I05 only on `tyk/i05` after its wave entry gate. Read AGENTS.md; preserve user changes. Effort M; code-review required. |
| Files | crates/packetcraftr-netio/src/platform/{dispatch,interface_validation}.rs; crates/packetcraftr-netio/src/route/{planner,error}.rs; crates/packetcraftr-netio/tests/error_contracts.rs; CHANGELOG.md |
| Evidence to verify | `crates/packetcraftr-netio/src/platform/dispatch.rs:103`; `crates/packetcraftr-netio/src/route/planner.rs:92`; `crates/packetcraftr-netio/src/route/error.rs:85`; `crates/packetcraftr-netio/tests/error_contracts.rs:38` |
| Scope and constraints | Netio interface-validation and route-semantics error conversion paths and owned error definitions/tests. Preserve exact bytes, scope/timestamps, finite input/resource budgets and original typed causes. Keep native resources in netio, workflow policy outside core, unsafe only in netio platform with SAFETY comments. Use fixtures/loopback/documentation addresses; retain authorization before discovery and final endpoint/byte checks. Delete superseded paths; add no general framework. |
| Done criteria | Error::source() retains actual validation/semantic causes, including through the real conversion helpers; existing classification codes remain stable. Source chains avoid duplicate messages; locally constructed route failures still work without an invented source. Document any changed public error fields. Add user-visible/breaking changes to Unreleased and keep affected schemas/examples/docs/release assets synchronized. |
| Verification and handoff | Run `cargo test --locked -p packetcraftr-netio --all-features` and `cargo test --locked -p packetcraftr --test error_classification_contracts`; exercise actual conversion helpers, source downcasts/chains, stable classifications and no duplicated causes. Run rustfmt and affected Clippy checks. Report changed files, exact check results, unresolved platform checks and any scope/size change; if effort grows to L, add both L gates. Do not publish, merge or execute other backlog tasks. |

### I06 — Consolidate release archive smoke checks

| Prompt component | Instruction |
|---|---|
| Task | Implement I06 only on `tyk/i06` after its wave entry gate. Read AGENTS.md; preserve user changes. Effort M; code-review required. |
| Files | .github/workflows/release.yml; scripts/build-manifest.py; one focused scripts/ archive verifier and behavioral tests |
| Evidence to verify | `.github/workflows/release.yml:269`; `.github/workflows/release.yml:285`; `.github/workflows/release.yml:327`; `.github/workflows/release.yml:332`; `.github/workflows/release.yml:369` |
| Scope and constraints | One standard-library Python archive verifier replacing duplicate Unix/Windows assertion blocks; retain extraction/runtime checks. Preserve exact bytes, scope/timestamps, finite input/resource budgets and original typed causes. Keep native resources in netio, workflow policy outside core, unsafe only in netio platform with SAFETY comments. Use fixtures/loopback/documentation addresses; retain authorization before discovery and final endpoint/byte checks. Delete superseded paths; add no general framework. |
| Done criteria | Both archive paths invoke the same verifier for required nonempty files, build identity, version, exact build/dissect bytes, NDJSON sequence/schema/completion and packaged examples. Fail on missing assets, nonzero commands, corrupt identity or malformed output. Delete duplicate checks; retain Unix executable checks, Windows extraction and Linux clean-runtime/linkage checks. Add user-visible/breaking changes to Unreleased and keep affected schemas/examples/docs/release assets synchronized. |
| Verification and handoff | Run the shared verifier on extracted Unix and Windows archives through the existing release matrix; exercise missing/empty asset, bad identity/version, nonzero child command, byte mismatch and malformed/unterminated NDJSON failure fixtures locally. Preserve Linux clean-container/runtime and pcap-free linkage smokes; do not publish a release to validate this task. Run rustfmt and affected Clippy checks. Report changed files, exact check results, unresolved platform checks and any scope/size change; if effort grows to L, add both L gates. Do not publish, merge or execute other backlog tasks. |

### I07 — Truncate completed stats tables directly

| Prompt component | Instruction |
|---|---|
| Task | Implement I07 only on `tyk/i07` after its wave entry gate. Read AGENTS.md; preserve user changes. Effort S; no dedicated task review gate. |
| Files | crates/packetcraftr-cli/src/commands/stats/mod.rs; crates/packetcraftr-cli/tests/offline_workflows.rs |
| Evidence to verify | `crates/packetcraftr-cli/src/commands/stats/mod.rs:72`; `crates/packetcraftr-cli/src/commands/stats/mod.rs:78` |
| Scope and constraints | Only stats cap_table ownership/omitted-row calculation; retain shared Retained for its other consumers. Preserve exact bytes, scope/timestamps, finite input/resource budgets and original typed causes. Keep native resources in netio, workflow policy outside core, unsafe only in netio platform with SAFETY comments. Use fixtures/loopback/documentation addresses; retain authorization before discovery and final endpoint/byte checks. Delete superseded paths; add no general framework. |
| Done criteria | Compute omitted count from original vector length and truncate in place; preserve table order, diagnostics, text/JSON parity and fragment-table exception for absent, zero, below/equal/above-length limits. Existing offline workflow tests pass; no new abstraction. Add user-visible/breaking changes to Unreleased and keep affected schemas/examples/docs/release assets synchronized. |
| Verification and handoff | Run `cargo test --locked -p packetcraftr-cli --no-default-features --test offline_workflows`; use existing public behavior coverage and targeted CLI checks for absent/zero/equal/oversized --top. Do not add tests that inspect source layout or mirror Vec::truncate. Run rustfmt and affected Clippy checks. Report changed files, exact check results, unresolved platform checks and any scope/size change; if effort grows to L, add both L gates. Do not publish, merge or execute other backlog tasks. |

## Review and cleanup role prompts

| Role | Self-contained prompt |
|---|---|
| code-review | Read AGENTS.md, the assigned task row above and its diff/tests. Check observable done criteria, actual failure paths, crate ownership, bounded resources, exact evidence and contract synchronization. Report actionable findings with path:line; make no edits. Task agent fixes findings before integration. |
| debt-collector | Read AGENTS.md and the task/wave diff. Inspect touched files and their callers for code, wrappers, exports, tests or config made obsolete by these changes. Delete only proven dead/duplicate artifacts and keep one domain-owned implementation; retain meaningful regressions, unknown bytes and all authorization/resource boundaries. Do not broaden scope. Run affected tests, formatting and Clippy; report removals or an evidence-backed no-op. |

## Execution log

- Wave 0 complete: finish-partials and debt-collector audits found only intentional fail-closed providers, lifetime/trait test helpers and consumed public exports; no cleanup changes. Passed `cargo fmt --all -- --check`, `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`, and `cargo test --locked --workspace --all-features` (including doctests).
- Wave 1 in progress: I04, I05 and I06 in isolated `tyk/i04`, `tyk/i05`, `tyk/i06` worktrees.

- I05: committed and independently reviewed with no findings; netio all-feature tests and affected Clippy passed. Integrated typed sources and migration note.
- I06: committed and independently reviewed with no findings; six stdlib fixture tests passed, real extracted Linux all-feature archive verifier passed, and Ubuntu 24.04 clean-runtime smoke passed with libpcap linkage confirmed. Native Windows/macOS archive execution remains pending CI.
- I06 follow-up: independent review accepted strict read-event checking and real tar/ZIP extraction smokes in native CI jobs. Seven local Python tests passed with the real Linux binary. Pcap-free extracted archive verification, absent libpcap linkage, and clean Ubuntu 24.04 runtime smoke also passed.
- I04: integrated after independent review and correction of non-IN RDATA interpretation. Portable core/workflow/CLI tests, doctests, schemas/examples, both rustfmt checks and full Clippy passed. DNS fuzz smoke: 85,975 executions in 31 seconds, no crash. Task debt removed duplicate name-error mapping/adapters and unused offset; 6 core record and 27 workflow wire regressions plus full Clippy passed.
- Wave 1 integrated; final wave cleanup and full workspace validation in progress.
- Wave 1 local exit gate passed: both format checks, full all-target/all-feature Clippy with warnings denied, and full workspace all-feature tests/doctests. Final integrated debt pass found no further removals. Native CI matrix is pending before the next wave.
- Wave 1 complete: [CI run 34257584002](https://github.com/tyk-swe/pcr/actions/runs/34257584002) passed all five jobs, including native archives on Windows and both macOS architectures. API docs with `RUSTDOCFLAGS="-D warnings"` passed; integrated DNS fuzz completed 87,007 executions in 31 seconds without a crash.
- Wave 2 in progress: I03 explicit TCP composition and I07 in-place stats truncation.
- I07 integrated: `offline_workflows` passed 32 tests; CLI portable all-target Clippy and rustfmt passed. Targeted CLI checks covered every stats table, absent/zero/below/equal/above limits, ordering, diagnostics, text/JSON parity, and the fragments exception.
- I03 integrated after independent review with no findings. Netio/workflow/CLI all-feature and portable suites (including doctests, endpoint/route refusals, framing/timeouts and cancellation) passed; full workspace all-target/all-feature Clippy and rustfmt passed. Migration/profile notes and new TCP CODEOWNERS routing are updated.
- Wave 2 final integrated cleanup and common validation in progress.
