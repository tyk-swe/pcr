# Testing policy

Every test must name a project behavior and fail for a plausible defect in that behavior. Assertions about private counters, allocation layouts, incidental dependency defaults, current time, installed software versions, or external services do not establish a project contract. Check returned packets, decoded fields, events, diagnostics, exit status, or filesystem effects instead. Rejection alone is enough when rejecting the input is the complete contract.

Use controlled input and independently expected output. A round trip or agreement between two implementations is useful supplementary evidence, but neither alone rules out a shared defect. Protocol vectors must cite their specification and the date checked when an external fact is load-bearing. Read constants and fixtures that the project owns rather than pinning facts supplied by an installed dependency.

Workflow tests use injected providers and clocks. A synchronization test may use real threads when thread lifetime or admission is the behavior being tested. Coordinate entry and release explicitly and bound every wait. Mock calls only when the interaction is the contract, such as rejecting transmission before authorization. Test budget refusal while data is retained, then successful work after release, rather than inspecting bookkeeping fields.

Keep regressions in their existing owning test file. Inline Rust tests belong with their module and separate Rust tests belong in that module's `tests.rs`. Python uses `scripts/tests/test_<module>.py`. A new feature can have a new mapped file. Do not add per-ticket suites. Modified helpers must be typed and follow AGENTS.md, including its comment and suppression rules.

# Review checklist

A reviewer must be able to identify the protected behavior, a representative defect that would fail the assertion, the controlled inputs or synchronization, and why the test belongs in its chosen file. Check that an upstream release, the clock, or unrelated machine state cannot cause failure. Automated mutation checks supplement this review.

# Local checks

The normal Python runner remains unittest.

```sh
python3 -m unittest discover -s scripts/tests -v
python3 -O -m unittest discover -s scripts/tests -v
cargo test --locked --workspace --lib --all-features
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

CI also retains the portable, default, layer 2, layer 3, minimum Rust version, documentation, macOS and Windows checks. Use the narrow affected tests during repairs and the complete CI matrix before requesting review.

# Mutation checks

`.config/mutation.toml` pins cargo-mutants and Cosmic Ray and maps every Python production module, including repository tools, to its tests. `requirements-dev.txt` installs Cosmic Ray. Install cargo-mutants with the version in that file's companion TOML configuration.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
cargo install cargo-mutants --version 27.1.0 --locked
python3 scripts/run_mutation.py select --full --plan mutation-plan.json
.venv/bin/python scripts/run_mutation.py run --plan mutation-plan.json --language python
python3 scripts/run_mutation.py check --plan mutation-plan.json --language python
python3 scripts/run_mutation.py run --plan mutation-plan.json --language rust --profile all
python3 scripts/run_mutation.py check --plan mutation-plan.json --language rust
```

For a PR, use `select --base BASE_SHA` instead of `--full`. Selection uses both sides of deleted or renamed files. Rust production edits select whole changed files. A separate or inline test change selects its whole crate. Crate dependency changes select all Rust crates. Python tests select their mapped modules. Shared test support selects every affected language module. Shared fixtures, workflow or mutation configuration, root dependencies and testing policy changes select both language suites. Unknown Python production modules fail selection until ownership is recorded.

The runner takes one snapshot of tracked and untracked, nonignored source before a run, then gives each target a disposable copy. It records the commit and a digest of that source snapshot. Cargo-mutants runs workspace tests against every selected mutant, so dependent crates can detect errors. When a package has a `build.rs`, the disposable manifest exposes it as an additional binary target so cargo-mutants can discover it. The amended manifest is retained with the results. Rust shards are numbered from one at this script's interface and translated to cargo-mutants' zero-based numbering. No mutant is sampled or silently removed.

The existing weekly CI schedule calls the full mutation workflow. PRs call the same workflow with scoped selection. Manual dispatch runs a full audit. Pushes to the default branch retain normal CI without repeating the full mutation audit. Rust runs on the existing Linux, ARM and Intel macOS, and Windows images with each supported feature profile. Eight shards per profile use one mutation worker per job, with at most four Rust jobs at once. These limits do not alter existing CI concurrency. The gate requires every platform, profile and shard, then combines their outcomes per crate. A mutant is killed when any required run catches it. Code disabled in one profile can be tested by another. A timeout never creates a kill, and a mutant is compilation-invalid only if every run that discovered it fails compilation. Python modules are checked separately. A score aggregated across modules or crates cannot make a weak group pass.

A group's score is killed mutants divided by eligible viable mutants and must be strictly greater than 90 percent. Timeouts remain in the denominator and never count as kills. Only compilation-invalid mutants and individually reviewed equivalent mutants are excluded. The checker requires a successful baseline, complete inventory, consistent shard metadata, actual test execution evidence, and results for every selected mutant. Missing reports, duplicate results, runner failures and unfinished runs fail the gate. Zero eligible mutants are reported as not applicable with the selection reason, including the invalid and equivalent counts.

Equivalent exclusions belong in `.config/mutation-exclusions.json`, one exact mutant per entry with `group`, `revision`, `identity`, and a nonempty `evidence` explanation. They apply only to that exact source revision and surviving mutant. Do not add broad patterns or exclusions merely to meet the score. Review every survivor even when the score passes.

Artifacts retain the selection plan, source revisions and digests, tool versions, raw tool reports, session databases, individual outcomes, diffs, logs, exclusions and per-group scores. The gate rejects reports from another commit, source snapshot or tool version and never treats absent artifacts as success. Python mutant identities include their source span and operator rather than a session-specific job identifier. For tool report semantics, see [cargo-mutants workspace testing](https://mutants.rs/workspaces.html), [its warning about test-only diffs](https://mutants.rs/in-diff.html), and [Cosmic Ray sessions](https://cosmic-ray.readthedocs.io/en/latest/tutorials/intro/index.html).

# Audit record

The initial inventory contained 282 Rust tests and 50 Python tests. The initial all-features Rust baseline and Python baseline passed. The Rust mutation inventory contained 26,453 candidates before repairs. These counts describe this audit's starting point and are not assertions in the test suite.

| Subsystem | Disposition and protected behavior |
| --- | --- |
| Message streams | Replaced private buffer counts with successful follow-on decoding under a small budget. Check complete message bytes and source frame identities. Retained SIP framing, gap, reset and unsupported-version cases. |
| Provenance | Replaced exact copy counts, tree comparisons and memory-layout charges with ordered independent source expectations, immutable published snapshots, budget refusal, shared-owner lifetime and admission after release. |
| Scan correlation | Removed comparison instrumentation and private map-layout assertions. Check direct and quoted reply ownership, retirement and reuse of admission. The retirement fixture constructs transport fields without assuming unregistered ports. |
| Packet preparation | Removed exact build-work instrumentation. Kept fresh-route, authorization, changed source and MTU checks. Replaced allocation-layout checks with bounded admission and independently decoded packet destinations, ports and payloads. |
| DNS security evidence | Replaced private grouping-map assertions with emitted finding suffix and distinct-label counts. |
| Policy resolution | Injected a refusing resolver so denial tests detect provider calls without relying on external DNS. |
| CLI decode selectors | Replaced a success-only assertion with the actual selected UDP codec. |
| CLI ranges and stream selectors | Reviewed decimal syntax, one-based positions, frame selection, timestamp scaling and scan-selection cases. Added range/sampling intersection, endpoint bounds, malformed-range diagnostics and complete TCP/UDP stream identities. |
| Python JSON support | Replaced interpreter allocation measurements with all values preserved and nonfinite values rejected in a wide document. |
| Mutation enforcement | Added behavioral checks for strict score boundaries, weak groups, incomplete and duplicate results, timeouts, worker failures, shard coverage, deleted tests, shared inputs, source identity and disposable source snapshots. A real two-crate fixture verified that dependent-crate tests kill all five mutants. |
| Native workers and cleanup | Cleanup tests now verify admission refusal while work or owner destruction is blocked and admission after release. Runtime, capture and native worker cases still need a full review. |
| CLI serialization | Application and stream cases now verify complete flushed records, byte-budget refusal, terminal errors and worker admission after cancellation. Followup, machine rendering and remaining serialization cases still need review. |
| Scan scheduling | Replaced work counters with due-only expiry, retirement behavior, unique host/endpoint completion and bounded progress. The conservative scheduler comparison and remaining private-state checks still need review. |
| Python forwarding | Added controlled rule-budget boundaries, complete signed timestamps, exact declared-check matching and invalid-command rejection after inspecting initial survivors. Full per-module scores are still pending. |
| Protocol suites and remaining tests | Review every case, consolidate misplaced review suites, add independent expected fields where only round trips or shared implementations are compared, and cite independent vectors. Full mutation scores and the native CI matrix are still outstanding. |
| Build scripts | Added disposable binary targets for package-root `build.rs` files. A two-crate integration fixture killed all nine mutants, including deletion of the build script's configuration output. The real build scripts still require full-run survivor review. |

The audit is not complete until every existing test has a disposition, the remaining violations are repaired, and the final revision passes every required full mutation group and CI profile. Passing ordinary tests does not establish that result.
