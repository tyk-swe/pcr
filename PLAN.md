# Execution plan

| Baseline | Capacity | Schedule | Status |
|---|---|---|---|
| `9a6803ee0c6b06c8e0c60373a4908c018acd374f` | One coordinator + at most three workers | Four waves including Wave 0; seven independent tasks in Tier 0 | Completed I12–I18 on `tyk/implement-plan`; all task/wave gates and available Linux/MSRV checks passed. Native macOS/Windows checks require those hosts. |

## Dispatch and gates

| Rule | Instruction |
|---|---|
| Worker prompts | Dispatch one worker per task. Send the common prompt, the complete task row and the validation table together so each assignment contains its files, constraints and done criteria. |
| Isolation | Use isolated checkouts and `tyk/<task>` branches when execution begins. Integrate serially; the coordinator reconciles shared changelog/docs/test hunks. Use separate Cargo target directories across concurrent checkouts; serialize feature-profile tests within a checkout to avoid shared CLI binary interference. |
| Capacity | Reuse idle worker threads for queued tasks and review roles. Reviewers must differ from the task's implementer. Queue gates within the same three-worker limit. |
| S gate | No task-specific review gate; applicable validation and the wave debt pass still apply. |
| M gate | One `code-review` agent after implementation; resolve findings and rerun invalidated checks. |
| L gate | One `code-review` agent, then a task `debt-collector` agent. None of the current tasks is L; apply this gate if scope is re-estimated as L. |
| Wave gate | After integration, one `debt-collector` pass over all files touched in that wave. A no-op with evidence is valid. |
| Scope changes | Recheck dependencies and scheduling when Wave 0 or implementation changes a task's scope; do not silently expand a task. |

| Common prompt — include verbatim in every task assignment |
|---|
| Work only on the assigned task and read applicable AGENTS.md instructions first. Preserve the acyclic core → netio/workflow → CLI separation, canonical public paths/model naming, checked arithmetic and the netio platform-only unsafe boundary. Preserve live authorization and finite traffic/state budgets; use injected providers, loopback, documentation addresses or isolated fixtures. Prefer deletion and existing mechanisms. Add no framework, configuration or unrelated cleanup. Synchronize schemas/examples when serialized output changes; keep envelopes, existing enum vocabularies and packet inputs strict. Record user-visible changes in Unreleased and document actual Rust/CLI breaking changes. Run the applicable checks below and report exact commands/results plus unavailable platform checks. Follow Conventional Commits, linked-issue/impact/validation PR requirements and applicable CODEOWNERS if a PR is requested. |

## Waves

| Wave | Entry condition | Concurrent tasks | Gates | Exit condition |
|---|---|---|---|---|
| 0 | Implementation requested; baseline and workspace instructions read | `finish-partials` only, using the prompt below | Size any actual cleanup S/M/L and apply its task gate; integrated wave debt-collector | Genuine partials completed or removed; intentional cases retained with evidence. Applicable tests green, no new lint; update affected task scopes before Wave 1. |
| 1 | Wave 0 closed; I12, I14 and I17 have no prerequisites | I12 deadline clipping; I14 filter discovery; I17 contract documentation | I12/I14 code-review; I17 no task gate; integrated wave debt-collector | Three acceptance sets met, schema/examples consistent, applicable tests green, no new lint. |
| 2 | Wave 1 integrated and validated | I13 scan-setting removal; I15 IPv6 rendering; I18 read diagnostics | I13 code-review; I15/I18 no task gate; integrated wave debt-collector | Three acceptance sets met, scan migration recorded, applicable tests green, no new lint. |
| 3 | Wave 2 integrated and validated | I16 deferred report conversion | I16 code-review; integrated wave debt-collector | Output contracts preserved, applicable tests green, no new lint; current CI requirements satisfied or unavailable checks identified explicitly. |

| Scheduling rationale |
|---|
| Waves 1 and 2 fill all three worker slots; Wave 3 contains the remaining task. I13 follows I12 to avoid simultaneous scan fixture edits. I16 follows I14/I18 to avoid simultaneous edits to offline CLI contracts. Documentation/changelog hunks are integrated by the coordinator. These are scheduling constraints; all backlog dependencies remain empty. |

| Wave 0 — finish-partials prompt |
|---|
| Inspect the current checkout with `rg -n -e TODO -e FIXME -e XXX -e stub -e 'not implemented' crates scripts .github fuzz` and `rg -n -U 'fn[^;{]*\{\s*\}' crates -g '*.rs'`; inspect multiline/trait/closure bodies the searches miss. Check manifests, cfg usage, `scripts/check-features.sh`, call sites, exports and tests for genuinely unfinished or unused paths. Complete or remove those partials before new feature work, within existing contracts. Trace hits before acting: native unsupported stubs are intentional fail-closed behavior, empty bodies may be valid defaults/test doubles, and the dependency-only decrypt foundation is documented and enabled in the feature matrix. Preserve such intentional cases with evidence. If a finding overlaps I12–I18, reconcile its scope and completion status so it is implemented once. Return path:line evidence and any changes/checks; apply size gates and a wave debt pass. |

## Task prompts

| ID / worker | Files and implementation prompt | Done criteria and focused validation |
|---|---|---|
| I12 / `clip-timeouts` | In `crates/packetcraftr/src/probe/runner.rs` and `crates/packetcraftr/src/fuzz/run.rs`, clip child timeouts to the existing Deadline's remaining budget. Inspect `scan/executor.rs`, `traceroute/executor.rs`, `scan/engine.rs`, `traceroute/engine.rs`, `fuzz/executor.rs` and `probe/evidence/` under that same source root. Use `dns/engine.rs:503` as the existing pattern. Preserve permits and carry the effective request through execution, validation and response selection. Reject zero remaining time; keep cooperative boundaries and accounting. | Deterministic deadline/fake-executor regressions prove partial-budget clipping, zero/exhausted non-execution and rejection of evidence beyond the clipped window. Exercise scan, traceroute, fuzz and probe evidence tests in the workflow crate, plus affected progressive contracts; relevant default/offline/all-feature profiles pass. |
| I13 / `remove-scan-batch-size` | Remove the inert setting from `crates/packetcraftr/src/scan/{mod.rs,model/request.rs,plan.rs}` and `crates/packetcraftr-cli/src/commands/scan/{arguments.rs,mod.rs}`. Inspect `crates/packetcraftr/src/scan/executor.rs`, `crates/packetcraftr/src/probe/executor.rs` and `crates/packetcraftr-cli/src/system/exchange.rs` before replacing template capacity with 1. Delete obsolete checks/tests and wording, preserving one-probe correlation, pacing and independent evidence/capture bounds. | Extend existing scan budget behavior coverage in `crates/packetcraftr/src/scan/tests.rs`: otherwise valid one-probe budgets work; excess probes fail. Update callers and verify CLI help/removed-option behavior. Workflow/CLI checks pass across affected profiles. Unreleased states the removed flag/public field/default and migration; any resulting commit uses `!` and a `BREAKING CHANGE:` footer. |
| I14 / `discover-filter-fields` | Extend `crates/packetcraftr-core/src/registry/lookup.rs`, `crates/packetcraftr-cli/src/commands/protocols/mod.rs` and `crates/packetcraftr/src/output/protocols.rs` to enumerate stored filter bindings and show their semantics in stable order. Inspect `crates/packetcraftr-core/src/protocol/builtin/filter.rs`; do not copy its catalog. Add optional JSON metadata separately from parent `bindings`, synchronize `schemas/packetcraftr.output.v1.schema.json` and the protocol-detail example in `examples/documents/`. Preserve current fields/enums and grammar. | Direct aliases, `tcp.flags.syn`, `tcp.port` and `udp.port` are discoverable consistently in text/JSON; either-endpoint `!=` semantics are explicit. Exercise registry/filter contracts, CLI discovery in `crates/packetcraftr-cli/tests/offline_workflows.rs`, and real aggregate/schema/example tests. New metadata remains optional in schema validation. |
| I15 / `format-ipv6-endpoints` | Update `crates/packetcraftr-cli/src/commands/follow/rendering.rs`, `crates/packetcraftr-cli/src/commands/tls/rendering.rs` and `crates/packetcraftr-cli/src/commands/dns/rendering.rs`. Reuse standard `SocketAddr` formatting demonstrated in `crates/packetcraftr-cli/src/commands/stats/rendering.rs:31`. Distinguish numeric DNS addresses from hostnames without resolution; keep the change in text rendering. | Exercise IPv4/IPv6 follow and TLS reports and numeric/hostname DNS rendering with existing fixtures or a local rendering smoke. IPv6 endpoints are bracketed; hostname/IPv4 spelling and structured output are unchanged. Existing affected CLI/rendering tests pass; no new formatting framework or low-value test matrix. |
| I16 / `defer-packet-reports` | In `crates/packetcraftr-cli/src/commands/build/mod.rs` and `crates/packetcraftr-cli/src/commands/dissect/mod.rs`, defer `Report::from_built/from_decoded` until a JSON payload needs it. Inspect `crates/packetcraftr/src/output/{build.rs,dissect.rs}` and `crates/packetcraftr-core/src/document/convert.rs`. Render native packet bytes/names/diagnostics directly elsewhere, including avoiding report construction for JSON misses. Preserve public conversion APIs; add no output layer. | Existing build/dissect cases in `crates/packetcraftr-cli/tests/offline_workflows.rs` preserve bytes, text/layer order, errors, filter-miss stderr and JSON null/diagnostics. Exercise aggregate/schema contracts and inspect conversion call sites to confirm discarded paths skip the work. Keep both source limits and diagnostics ownership intact; affected profiles pass. |
| I17 / `correct-contract-docs` | Correct `schemas/EVOLUTION.md` and `crates/packetcraftr/src/output/mod.rs` rustdoc. Compare `CONTRIBUTING.md`, `.github/workflows/ci.yml`, `crates/packetcraftr/tests/published_example_matrix.rs`, `crates/packetcraftr/tests/aggregate_schema_conformance.rs` and the output schema. Delete obsolete exhaustive-coverage/semver-gate/closed-object claims. Keep the current serialized compatibility policy and pre-1.0 policy; change documentation only. | Claims match retained checks and the open-record/strict-envelope distinction. No removed job or test machinery is restored. Check the diff and links; warning-free rustdoc validates the changed API documentation. No new tests for this documentation repair. |
| I18 / `show-read-diagnostics` | Update `crates/packetcraftr-cli/src/commands/read/rendering.rs` to print existing `decoded.diagnostics` after each selected frame with clear source-frame attribution. Reuse `crates/packetcraftr-cli/src/rendering/human.rs`; inspect `crates/packetcraftr/src/output/frame.rs` and the capture fixtures in `crates/packetcraftr-cli/tests/offline_workflows.rs`. Keep diagnostics in their existing NDJSON location and preserve filtering, exit behavior and binary output. | Exercise a diagnostic-bearing capture in text/NDJSON and with a filter that removes its frame: matching codes/messages, clear frame attribution, and silence for the excluded frame. Existing read, NDJSON and capture-export contracts pass. No schema change or new diagnostics mechanism. |

## Validation and closing gates

| Situation / role | Required action |
|---|---|
| Task validation | Use focused existing tests; extend behavioral coverage for substantive deadline, budget or schema changes. Do not add tests that mirror implementation or build a new test framework. Run `cargo nextest run --locked -p <affected-crate> --profile ci` with the relevant filters and feature flags. For Rust changes, run fmt and applicable Clippy with `-D warnings`. Resolve failures before closing. |
| Feature profiles | Default: no extra flags. Offline: `--no-default-features`. All features: `--all-features`. Add pcap-free `--no-default-features --features native-route,native-layer3` when native composition is affected (I12/I13), and use `scripts/check-features.sh` for public feature changes. Linux all-feature checks require libpcap-dev. |
| Integrated waves | Tests green and no new lint for the integrated changes; run additional checks only when integration or cleanup invalidates earlier results. Documentation-only changes carry forward test evidence; I17 additionally needs rustdoc validation. |
| Final integration | Use current `.github/workflows/ci.yml`: Linux four-profile nextest, macOS/Windows default nextest and all-target/all-feature checks, MSRV no-default/all-feature checks, fmt (workspace and fuzz), dangerous-range/Quick Start scripts, feature matrix, all-target/all-feature Clippy, warning-free rustdoc, all-feature doctests, workspace dependency policy and fuzz advisories. Coverage remains manual; fuzz remains daily/manual; no patch-only semver gate. Reuse applicable CI evidence and identify unavailable native checks. |
| `code-review` prompt | Read the task's diff, complete acceptance criteria and exact validation results. Check behavior, compatibility, authorization/budgets, errors and test quality; return actionable path:line findings. Do not expand scope. The coordinator resolves findings before integration. |
| `debt-collector` prompt | Inspect only assigned task/wave touched files after implementation/integration. Remove dead paths, obsolete tests or unnecessary abstractions introduced or exposed by the work while preserving supported behavior, public contracts and intentional foundations. Report each removal or an evidence-backed no-op; rerun only invalidated checks. |
| Handoff | Record exact results and platform limits for each ID/wave. Mark tasks complete only when their acceptance criteria and gates pass. Historical validation for I01–I11 is available with `git show 9a6803ee:PLAN.md`; it is not evidence that these proposed tasks have run. |

## Execution results

Results below describe this implementation run; the task tables above retain the
accepted scope and gates. Linux validation uses the pinned Rust 1.97.1 and
cargo-nextest 0.9.143, with libpcap 1.10.6 available. Native macOS/Windows
execution requires their respective hosts.

- Baseline: `cargo build --locked --workspace` passed.
- Wave 0 audit and independent debt review found no genuine partials requiring
  changes. Native dispatch stubs remain fail-closed (`platform/dispatch.rs`);
  empty bodies are lifetime test doubles and compile-time trait assertions.
  The decrypt dependency foundation remains documented and included in
  `scripts/check-features.sh`. No I12–I18 scope changes were needed.
- Wave 0 validation: `cargo nextest run --locked -p packetcraftr-cli --profile ci
  --no-default-features --test capability_contracts` passed (2 tests). The audit
  and independent debt pass were no-ops; no implementation checks were invalidated.

### Wave 1

- I17 implemented (`docs(output): correct contract evolution guarantees`).
  `cargo fmt --all -- --check`, `git diff --check`, and relative link checks
  passed. `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace
  --all-features --no-deps` passed without warnings. Only documentation changed.

- I12 implemented and independently reviewed with no findings. The following
  command passed 82 tests in each of default, offline, pcap-free, and all-feature
  profiles (228 tests excluded by the focused filter):

  ```sh
  cargo nextest run --locked -p packetcraftr --profile ci <profile-flags> \
    -E 'test(scan) | test(traceroute) | test(fuzz) | test(probe) | test(progress)'
  ```

  Profile flags were empty, `--no-default-features`,
  `--no-default-features --features native-route,native-layer3`, and
  `--all-features`, respectively. After strengthening the exact-boundary
  fixture, `cargo nextest run --locked -p packetcraftr --profile ci
  <profile-flags> --lib -E 'test(fuzz::run::tests)'` passed 3 tests in each of
  the first three profiles; the all-feature 82-test run included that refinement.
  `cargo clippy --locked -p packetcraftr --all-targets --all-features --
  -D warnings`, formatting, and diff checks passed.
- I14 implemented and independently reviewed with no findings. The following
  focused command passed 40 tests in each default, offline, and all-feature
  profile (26, 27, and 26 excluded tests, respectively):

  ```sh
  cargo nextest run --locked -p packetcraftr-core -p packetcraftr \
    -p packetcraftr-cli --profile ci <profile-flags> \
    --test runtime_registry_contracts --test filter_contracts \
    --test aggregate_schema_conformance --test facade_output_contracts \
    --test published_example_matrix --test output_behavior \
    --test offline_workflows \
    -E 'binary(runtime_registry_contracts) | binary(filter_contracts) | binary(aggregate_schema_conformance) | binary(facade_output_contracts) | binary(published_example_matrix) | binary(output_behavior) | test(protocol)'
  ```

  `cargo clippy --locked -p packetcraftr-core -p packetcraftr
  -p packetcraftr-cli --all-targets --all-features -- -D warnings`, formatting,
  and diff checks passed. The protocol example was regenerated from the CLI;
  its existing result fields were unchanged.
- Serial integration required no code conflict resolution. Integrated
  `cargo fmt --all -- --check` and `git diff --check` passed.

- Independent Wave 1 debt review inspected all 22 touched files and returned
  an evidence-backed no-op. All Wave 1 acceptance sets and gates passed.

### Wave 2

- I15 implemented and integrated. Actual-renderer smoke verified IPv4/IPv6
  follow and TLS endpoints, numeric IPv4/IPv6 DNS servers, and mixed-case
  hostname preservation; DNS JSON server fields stayed unchanged. Temporary
  smoke-only fixture code was removed before final validation.
  The following command passed 35 tests in each default, offline, and
  all-feature profile:

  ```sh
  cargo nextest run --locked -p packetcraftr-cli --profile ci <profile-flags> \
    --bin packetcraftr --test offline_workflows --test tls_workflows \
    -E 'binary(tls_workflows) | test(follow) | test(tls) | test(dns)'
  ```

- I18 implemented and integrated. The new diagnostic fixture passed, and the
  following affected suite passed 56 tests in each default, offline, and
  all-feature profile:

  ```sh
  cargo nextest run --locked -p packetcraftr-cli --profile ci <profile-flags> \
    -E 'test(read) | test(capture_file) | binary(ndjson_conformance) | binary(normalized_capture_contracts) | binary(capture_stdin_contracts)'
  ```

  The initial focused command was `cargo nextest run --locked
  -p packetcraftr-cli --profile ci --no-default-features
  --test offline_workflows -E 'test(read_dissection_diagnostics)'` (1 passed).
- Both I15 and I18 passed `cargo clippy --locked -p packetcraftr-cli
  --all-targets --all-features -- -D warnings`, formatting, and diff checks.
  Their only merge conflict was resolved by preserving both changelog bullets.
  New fix entries were consolidated into the existing Unreleased Fixed section.
- I13 implemented, independently reviewed with no findings, and integrated.
  The following command passed 65 tests in default, 66 offline, 65 pcap-free,
  and 65 all-feature tests:

  ```sh
  cargo nextest run --locked -p packetcraftr -p packetcraftr-cli \
    --profile ci <profile-flags> \
    -E 'test(scan) | test(probe) | test(progress) | binary(progressive_active_contracts)'
  ```

  `cargo clippy --locked -p packetcraftr -p packetcraftr-cli --all-targets
  --all-features -- -D warnings`, formatting, and diff checks passed.
  The removed flag, public field, and default have a breaking migration entry.
- Integrated `cargo fmt --all -- --check` and `git diff --check` passed.
  No source conflicts invalidated task-level tests. Independent Wave 2 debt
  review inspected all 14 touched files and returned an evidence-backed no-op;
  all Wave 2 acceptance sets and gates passed.

### Wave 3

- I16 implemented, independently reviewed with no findings, and integrated.
  Each of default, offline, and all-feature profiles passed 14 CLI contracts
  and 14 aggregate/schema/example contracts with these commands:

  ```sh
  cargo nextest run --locked -p packetcraftr-cli --profile ci <profile-flags> \
    -E 'test(build) | test(dissect) | test(packet_documents_stdin) | test(malformed_recipe) | test(format_and_limit_failures)'
  cargo nextest run --locked -p packetcraftr --profile ci <profile-flags> \
    --test aggregate_schema_conformance --test facade_output_contracts \
    --test published_example_matrix
  ```

  `cargo clippy --locked -p packetcraftr-cli --all-targets --all-features --
  -D warnings`, formatting, and diff checks passed. Call-site inspection
  confirms report conversion occurs only in build JSON and matched dissect
  JSON branches; existing contracts now assert exact native output and
  diagnostic ownership.
- Independent Wave 3 debt review inspected all five touched files and returned
  an evidence-backed no-op. No source merge conflicts or edits invalidated
  task checks. Final full-workspace validation passed as recorded below.

### Checks reusable across waves

- `cargo +1.96.0 check --locked -p packetcraftr-core -p packetcraftr-netio
  -p packetcraftr --all-targets --all-features` passed after Wave 2. I16 only
  changes the CLI; final MSRV workspace checks also cover its integrated code.
- `cargo deny check`: advisories, bans, licenses, and sources passed.
- `cargo deny --manifest-path fuzz/Cargo.toml check advisories`: passed.
- Initial `cargo fmt --all -- --check`,
  `cargo fmt --manifest-path fuzz/Cargo.toml -- --check`, and
  `bash scripts/check-dangerous-ranges.sh` passed. Workspace checks were
  repeated after integration; fuzz sources are unchanged.

### Final integration

All seven tasks and four wave gates are complete. Independent task reviews
found no unresolved issues; each wave debt pass was an evidence-backed no-op.
The coordinator consolidated the new changelog entries into existing sections.
Final checks ran against the integrated implementation on Linux, with
Rust 1.97.1 and MSRV 1.96.0.
The four nextest profiles produced **4,196 passing test executions**, with
no failures or skipped tests.

| Exact command | Result |
|---|---|
| `cargo nextest run --locked --workspace --profile ci` | 1043 passed; 0 skipped |
| `cargo nextest run --locked --workspace --profile ci --no-default-features` | 1026 passed; 0 skipped |
| `cargo nextest run --locked --workspace --profile ci --no-default-features --features native-route,native-layer3` | 1052 passed; 0 skipped |
| `cargo nextest run --locked --workspace --profile ci --all-features` | 1075 passed; 0 skipped |
| `cargo fmt --all -- --check` | Passed |
| `cargo fmt --manifest-path fuzz/Cargo.toml -- --check` | Passed |
| `bash scripts/check-dangerous-ranges.sh` | Passed |
| `bash scripts/check-quick-start.sh` | Passed |
| `bash scripts/check-features.sh` | All 9 profiles passed |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed |
| `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps` | Passed |
| `cargo test --locked --workspace --all-features --doc` | 11 passed; 1 ignored |
| `cargo +1.96.0 check --locked --workspace --all-targets --no-default-features` | Passed |
| `cargo +1.96.0 check --locked --workspace --all-targets --all-features` | Passed |
| `cargo deny check` | Advisories, bans, licenses, and sources passed |
| `cargo deny --manifest-path fuzz/Cargo.toml check advisories` | Passed |

Dependency-policy and fuzz-advisory checks were carried forward from this run;
no manifests or lockfiles changed. Final `git diff --check` also passed.
Coverage and fuzz campaigns remain manual/daily checks as defined by current CI;
no removed semver or exhaustive-example gate was restored.

Native macOS/Windows default nextest and all-target/all-feature checks were not
run because this environment is Linux. They remain the platform-specific CI
checks; Linux feature profiles do not substitute for execution on those hosts.

The breaking migration is recorded in Unreleased: remove scan's `--batch-size`,
`scan::Limits::batch_size`, and `scan::DEFAULT_BATCH_SIZE` usages. Rust
`output::protocols::Detail` struct literals must supply `filter_fields`;
`Detail::new` retains its existing signature.
