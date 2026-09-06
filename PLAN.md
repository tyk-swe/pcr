# Parallel execution plan

| Status | Capacity | Schedule |
|---|---|---|
| All 11 tasks implemented; validation and platform limits below | Coordinator + at most 3 worker agents | 5 waves: mandatory preparation + 4 implementation waves; 11 tasks fill 3/3/3/2 slots |

## Dispatch and gates

| Rule | Instruction |
|---|---|
| Self-contained prompts | Send each worker the common prompt below plus its complete task-table row. Include the validation rules below. Never dispatch an ID alone. |
| Isolation | One agent per task; use isolated checkouts/branches named `tyk/<task>`. Integrate completed tasks serially. Shared changelog, README and test-file hunks are reconciled by the coordinator before the wave exits. |
| Dependencies | I01 requires I05. Later placement also separates edits to input.rs, read/follow command modules and TLS handling. I02 has no semantic dependency on I01, but follows it to avoid concurrent read-path edits. |
| S gate | No per-task review agent; run the relevant validation. |
| M gate | One `code-review` agent after the task. |
| L gate | One `code-review` agent, then one task-specific `debt-collector` agent; remove leftover dead code/abstractions and resolve findings. |
| Every wave | After integration and task gates, run one `debt-collector` over that wave's touched files; remove only evidenced leftovers, then validate any changes it makes. No cleanup means no gratuitous edits. |
| Capacity | Review/cleanup agents use freed worker slots; never exceed three children. These are future roles, not required installed agent types. |

Common prompt:

> Work only on your assigned task in `/home/ubuntu/code/pcr/2/pcr`. Read current `AGENTS.md` and relevant files before editing. `C` means `crates/packetcraftr-cli`, `W` means `crates/packetcraftr`, and `K` means `crates/packetcraftr-core`. Preserve the acyclic core → netio/facade → CLI responsibilities, canonical public paths, public source compatibility, live authorization and finite budgets. Keep unsafe confined to existing netio platform boundaries, use checked operations and existing helpers, and use loopback/documentation-address fixtures. Prefer deletion; introduce no framework or speculative layer. Keep schema/example contracts synchronized if affected, and supply an Unreleased note for user-visible changes. Implement the scope and done criteria in your row, run the relevant checks below, and return changed files, exact commands/results and any unresolved limitation. Do not publish or merge a PR.

## Waves

| Wave | Entry condition | Concurrent tasks | Gates | Exit condition |
|---|---|---|---|---|
| 0 | Execution authorized; baseline and workspace instructions read | `finish-partials` only, using the prompt below | Size any actual cleanup S/M/L and apply its gate; then wave debt-collector | Real partials completed/removed or explicitly retained with evidence; affected tests green, no new lint; no speculative work smuggled into cleanup |
| 1 | Wave 0 exits; revalidate evidence if cleanup changed it | I04 (L), I05 (S), I08 (S) | I04 code-review + task debt-collector; then wave debt-collector | Blocked output regressions and affected stream/TLS tests green; ownership mapping checked; no new lint |
| 2 | Wave 1 exits | I06 (M), I07 (S), I10 (S) | I06 code-review; then wave debt-collector | Recipe parity and DNS fixture tests green; archive smoke checks pass for affected platforms; no new lint |
| 3 | Wave 2 exits; I05 integrated | I01 (M), I09 (S), I11 (S) | I01 code-review; then wave debt-collector | Piped-capture and retention tests green; nextest coverage produces LCOV; no new lint |
| 4 | Wave 3 exits; read-path edits integrated | I02 (M), I03 (S) | I02 code-review; then wave debt-collector | Normalized capture and selector tests green; final required CI gates green, no new lint; all acceptance criteria resolved |

Wave 0 `finish-partials` prompt:

> Inspect the repository read-only first. Search with `rg -n 'TODO|FIXME|XXX|stub|not implemented' crates scripts .github`, then inspect empty functions, unused exports/tests and feature flags never exercised; use manifests, feature-matrix configuration and call sites to distinguish partial work from intentional behavior. Complete or remove demonstrated partials before new work, with the smallest change and applicable tests. Preserve intentionally fail-closed native stubs, public APIs and the documented dependency-only decrypt foundation; marker absence or an apparently unused public export is not proof of dead code. If there are no real partials, report a no-op. Report evidence and size for each change so the coordinator applies the proper gate; do not start backlog features during this pass.

## Task prompts

| Agent | Files and concrete assignment | Done criteria / focused validation |
|---|---|---|
| I04 | Inspect `W/src/output/stream.rs`, `W/src/progress.rs`, `C/src/startup.rs`, `C/src/rendering/ndjson.rs`, `C/src/commands/dns/mod.rs`, `C/src/commands/target_workflow.rs` and all progressive completion callers. Fix the encoder-lock wait during timeout cleanup and the synchronous terminal-write escape. A nonblocking state query alone is insufficient; preserve public APIs and existing worker lifetime guarantees. | Releasable blocked writers prove cleanup and terminal publication are bounded; a subprocess with stalled stdout exits within budget plus a bounded shutdown allowance. Successful output has contiguous sequences/exactly one terminal; unavailable output becomes an incomplete-stream failure without blocking again. Extend `W/tests/progressive_active_contracts.rs`, existing encoder tests and `C/tests/process_contracts.rs`/`ndjson_conformance.rs`; affected default/offline/all-feature tests pass. |
| I05 | In `C/src/commands/tls/mod.rs`, delete `count_tcp_streams` and its missing-selector reopening path. Use existing first-pass `frames_matched` evidence and an absence-only diagnostic; do not add fields to `K/src/analysis/pipeline/mod.rs::Summary`. | Absent/empty-capture selectors return invocation errors after one pass; normal selection and NDJSON terminal behavior remain correct. Update diagnostic expectations in `C/tests/tls_workflows.rs`, including the range assertion, and Unreleased wording. |
| I08 | Inspect `.github/CODEOWNERS`, current `K/src/protocol/` paths and ownership history. Delete stale `protocol_catalog.rs`/`protocol/support.rs` patterns and their orphaned comment as appropriate; verify last-match routing of current catalog and contract files. | Representative current files retain intended existing owners. Preserve the explicit single-owner builtin registry exception unless history proves it needs changing. Return a small path → effective-owner comparison; no new ownership tool or test framework. |
| I06 | Fix recipe format selection in `C/src/input.rs` using existing parsers. Inspect `C/tests/offline_workflows.rs` and `examples/documents/packet-raw.yaml`. Support YAML comments and reordered keys on stdin without disrupting JSON or packet expressions. | File/stdin parity tests cover comment-first and reordered YAML, JSON, packet expressions, malformed input and existing size/terminal restrictions. Relevant offline workflow tests pass; document user-visible behavior. |
| I07 | Update Unix and Windows staging/smoke sections in `.github/workflows/release.yml`. Package `examples/captures/tls-handshake.pcapng` and `examples/documents/packet-ipv4-udp.json`, preserving the relative paths used by README. | From extracted archives outside the checkout, run the README read/TLS/build fixture commands. Both packaging paths include fixtures and retain existing asset/version/schema/attestation checks. Exercise packaging locally where supported and require the remaining platform smoke checks before closing. |
| I10 | Repair the loopback fallback fixture in `W/src/dns/tests.rs`, using the bounded acceptance pattern in `W/tests/dns_tcp_contracts.rs`. Bound accept, socket reads/writes and thread cleanup; avoid a reusable server framework. | Existing fragmented-response fallback test passes; a controlled no-connection case proves finite fixture termination without needing the test runner to kill it. Run the affected DNS unit/contract tests on offline/default profiles; preserve loopback-only traffic. |
| I01 | After I05, adapt `C/src/input.rs` and offline `read`, `expert`, `follow`, `stats`, `tls` command argument/help and reader call sites to accept `-`, using `K/src/analysis/pcap/reader.rs`'s generic Read support. Inspect `C/src/commands/replay/mod.rs` because it shares the opener; keep live replay file-based. | File and piped PCAP/PCAPNG results agree across the five commands, including binary rewrite and absent TLS selectors; empty/malformed/truncated input and finite resource ceilings retain errors. Reject terminal stdin. Add CLI/process regressions and docs explaining synchronous reads may block between duration checks; no cancellation framework. |
| I09 | Change `.github/workflows/coverage.yml` to use installed nextest through llvm-cov with profile ci. Reuse `.config/nextest.toml`; do not duplicate timeout settings or change coverage scope. | Run `cargo llvm-cov nextest --locked --workspace --all-features --profile ci --lcov --output-path lcov.info` using the supported installed CLI, adjusting syntax only if required. Confirm the effective inherited timeout and nonempty LCOV; preserve artifact upload. |
| I11 | Adapt existing `Retained` in `C/src/commands/offline_analysis.rs` to defer conversion until capacity exists. Update follow/TLS aggregate callers in `C/src/commands/follow/rendering.rs` and `C/src/commands/tls/rendering.rs`; inspect allocations in `W/src/output/follow.rs` and `W/src/output/tls.rs`. | A conversion-count regression proves no conversion at capacity and correct retained/omitted counts. Selected-session counts and text/raw/hex/NDJSON outputs remain unchanged. Run retention and affected aggregate/stream contract tests; no second admission abstraction. |
| I02 | Extend `C/src/commands/read/{arguments.rs,mod.rs}` with explicit normalized PCAPNG export using `K/src/analysis/pcap/writer.rs`. Preserve source-record rewriting by default; avoid adding classic-PCAP conversion combinations or a capture-export layer. | Round-trip tests cover filtered physical frames, empty matches, multi-section/interface mapping, timestamps and resource/output limits. Reject unrepresentable timestamp-less frames clearly, without invented metadata; document metadata loss and the opt-in flag. Existing source-fidelity rewrite tests remain green. |
| I03 | In `C/src/commands/follow/mod.rs`, reject an absent TCP/UDP selector using existing matched-frame evidence. Inspect `K/src/analysis/follow.rs` and existing CLI follow tests; do not add another capture scan or confuse missing data with missing streams. | CLI regressions cover absent/empty captures, valid payload-free TCP and empty UDP, raw output and NDJSON error termination. Normal extraction remains unchanged; update Unreleased for the changed exit behavior. |

## Validation and closing gates

| Situation | Required action |
|---|---|
| Every implementation wave | Finish intended edits first, then run focused `cargo nextest run --locked -p <affected-crate>` filters under affected default/`--no-default-features`/`--all-features` profiles; batch independent checks. Run fmt and applicable Clippy with `-D warnings` for Rust edits. Resolve findings before exit. |
| Documentation/config-only tasks | Validate the concrete changed behavior (archive smoke, coverage generation, owner matching); Rust test/lint state carries forward when no Rust input changed. Do not add implementation-mirroring tests for ownership or packaging text. |
| Final integration | Require repository CI: workspace nextest across supported profiles/platforms, all-feature doctests, rustdoc with `RUSTDOCFLAGS="-D warnings"`, fmt, all-target/all-feature Clippy, cargo deny, `scripts/check-features.sh`, and existing MSRV/semver gates. Linux all-feature work requires libpcap-dev. Reuse current successful CI evidence; rerun a check only if later edits invalidate it. |
| Review prompt | Read the assigned task's diff, acceptance criteria and recorded checks. Verify concrete behavior, source/output compatibility, bounds, failures and test quality. Return actionable findings with path:line; do not expand scope. |
| Debt-collector prompt | Inspect only the assigned task or wave's touched files after integration. Remove dead paths, duplicated machinery and unnecessary abstractions introduced or exposed by that work; preserve intentional foundations and public contracts. Explain each removal and rerun only invalidated checks; report no-op when nothing qualifies. |
| Final handoff | Record exact validation results and remaining platform limitations; do not claim unavailable checks passed. Any PR follows repository linked-issue, impact, Conventional Commit and applicable CODEOWNERS requirements. |

## Execution evidence

- Baseline: `26708188`; integration branch: `tyk/implement-backlog`.
- Wave 0: no-op after marker, empty-body, call-site and feature-matrix inspection. Native stubs are intentionally fail-closed; decrypt is a documented dependency-only foundation. No implementation changes or invalidated tests; no touched files for debt cleanup.
- Baseline `cargo build --locked -p packetcraftr-cli`: passed on Linux with Rust 1.97.1 and libpcap 1.10.6.
- I08: removed stale ownership routes. Last-match comparison of catalog, TLS model, IGMP, SCTP, matcher, builtin registry and registry registration paths passed; only the registry itself retains its existing single owner.
- Wave 1 complete: I05 TLS selector tests passed in default, offline and all-feature profiles (12 each), with fmt and CLI Clippy. I04 focused suites passed (35 default, 62 offline, 61 all-feature), followed by three final startup/process regressions; blocked stdout exited in approximately 1.12 seconds against a 200ms workflow budget plus a two-second allowance. A review removed unnecessary process-exit changes; task and integrated-wave debt reviews found no remaining removals. Affected all-target/all-feature Clippy and fmt passed.
- Wave 2 complete: I06 review passed, default/all-feature focused CLI tests passed (30 each), and all 31 offline cases passed after correcting and rerunning one test fixture. I10 DNS unit/contract tests passed in all three profiles (47 each), including no-client cleanup in approximately 64–69ms. Affected Clippy and fmt passed. I07 Unix tar and PowerShell 7.6.5 ZIP packaging and extracted README smoke scripts passed on Linux; ZIP validation used a Linux executable renamed `.exe` with executable permission restored in the disposable harness, so native Windows/macOS execution remains a CI requirement. The wave debt review corrected the new stdin example to use the packaged JSON fixture; that command passed from the extracted Unix archive.
- Wave 3 complete: I01 review passed; final sequential CLI suites passed (72 default, 74 offline, 72 all-feature), including Linux PTY terminal rejection and replay's file-only behavior. Early invalid fixtures/assertions were corrected; concurrent shared-binary profile interference was eliminated by serializing validation. I11 retention/output suites passed in all three profiles (42 each); affected Clippy and fmt passed. I09 ran `cargo llvm-cov nextest --locked --workspace --all-features --profile ci --lcov --output-path lcov.info`: 1,036 tests passed, zero skipped, and LCOV contained 6,675,838 bytes across 390 source records. Profile `ci` inherits the default 15-second slow timeout with termination after four periods. Wave debt review found no removals.
- Library closing checks: `cargo semver-checks check-release -p packetcraftr-core -p packetcraftr-netio -p packetcraftr --baseline-rev 26708188 --all-features --release-type patch` passed for all three libraries with no semver update required. `cargo test --locked --workspace --all-features --doc` passed (11 doctests, one intentionally ignored). Subsequent library edits only correct tests; public implementation is unchanged.
- Wave 4 complete: I03 focused suites passed (35 default, 36 offline, 35 all-feature). I02 isolated-target suites passed (44 default, 45 offline, 44 all-feature); review corrected timestamp documentation and fixtures to match the reader's existing exact-representability requirement. Affected Clippy and fmt passed. The integrated-wave debt review found no removals. All I01–I11 acceptance changes are implemented.
- Final test corrections: workspace validation exposed two scheduling assumptions in I04 regressions. The subprocess fixture now emits one large first TCP chunk instead of relying on many small records filling stdout within 200ms. The terminal-writer fixture waits for an explicit writer-entry signal before asserting its invocation count. Original output deadlines, incomplete-stream assertions, finite cleanup and worker-permit checks remain. Both selected regressions passed in all four profiles; the final debt review found no removals. No production fix was needed.

## Final validation

Final Linux builds used fresh `target/final`, feature/MSRV checks used `target/final-checks`, and cross-checks used `target/final-cross`, all from the integration checkout. Earlier cross-worktree artifact reuse was avoided. A temporary-filesystem quota interrupted some final regression reruns; those checks passed after moving `TMPDIR` and logs under `target/`.

| Check | Exact command / selection | Result |
|---|---|---|
| Workspace tests | `cargo nextest run --locked --workspace --profile ci`, with the profile flags below | Default: 1,029/1,029 passed. All-features: 1,061/1,061 passed. Offline: initially 1,011/1,012 passed; pcap-free: initially 1,037/1,038 passed. Their sole failures were the corrected fixtures above, which passed targeted reruns. Initial offline/pcap-free runs also reported 6/7 nextest leak warnings; default/all-feature runs reported none. |
| Corrected regressions | Command below, in all four profiles | 2/2 selected tests passed in each profile; unrelated tests were filtered out. Stalled stdout exited in approximately 1.1 seconds against a 200ms workflow budget plus a two-second allowance. |
| Workspace Clippy | `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed. |
| Final fixture Clippy | `cargo clippy --locked -p packetcraftr -p packetcraftr-cli --lib --test process_contracts --all-features -- -D warnings` | Passed after both corrections. |
| Formatting | `cargo fmt --all -- --check`; `cargo fmt --manifest-path fuzz/Cargo.toml -- --check` | Passed; workspace formatting checked again after fixture corrections. |
| Rustdoc | `RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps` | Passed. Doctests and semver results are recorded above. |
| Feature matrix | `bash scripts/check-features.sh` | All nine all-target workspace profiles passed. |
| MSRV | `cargo +1.96.0 check --locked --workspace --all-targets`, with offline, pcap-free and all-feature flags | All three passed. Final library-test correction also passed `cargo +1.96.0 check --locked -p packetcraftr --tests --all-features`. |
| Dependency policy | `cargo deny check`; `cargo deny --manifest-path fuzz/Cargo.toml check advisories` | Both passed. Dependencies are unchanged. |
| Repository smoke | `bash scripts/check-dangerous-ranges.sh`; `bash scripts/check-quick-start.sh /tmp/pcr-final-quickstart` | Both passed; Quick Start used a copy of the final all-feature executable. |
| Release archives | Current workflow's Unix and PowerShell package/extracted-smoke scripts, with final executable and README | Both passed, including recipe/capture stdin examples from both extracted directories. Packaged README matched the final source. PowerShell used the Linux executable renamed `.exe` with execution permission restored in the disposable harness. |
| Production portability | `cargo check --locked --workspace --all-features --target x86_64-apple-darwin`; same with `--target x86_64-pc-windows-msvc` | Both passed. |
| Native platform limits | Same cross-checks with `--all-targets` | Unavailable locally: unchanged `alloca` C dependency needs a macOS compiler/SDK or Windows `lib.exe`/MSVC tooling. Native macOS/Windows tests and release execution remain CI responsibilities; Linux PowerShell smoke does not establish native Windows execution. |

Profile flags: default uses no additional flags; offline uses `--no-default-features`; pcap-free uses `--no-default-features --features native-route,native-layer3`; all-features uses `--all-features`.

The final regression command was run with each of those four feature selections:

```sh
cargo nextest run --locked -p packetcraftr -p packetcraftr-cli \
  --lib --test process_contracts --profile ci --all-features \
  -E 'test(bounded_terminal_writes_fail_incomplete_without_retrying_or_releasing_the_worker) | test(stalled_ndjson_stdout_exits_within_the_budget_and_shutdown_allowance)'
```

Validation logs are in `/tmp/pcr-final-*.log`, with quota-recovery regression/Clippy logs under `target/validation-logs/`. Final archive logs are under `/tmp/pcr-i07-validation-imv541y8/final/`. The successful coverage run and LCOV evidence are recorded under Wave 3 above. No PR was published.
