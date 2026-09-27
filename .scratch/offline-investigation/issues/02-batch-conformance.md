# BASE-02: Prove and document the complete offline batch

Status: ready-for-agent
Blocked by: HTTP-T02, HTTP-B02, SPLIT-02, GATE-02
Size: small–medium integration and release work
Spec: [batch contract](../spec.md)

## What to build

1. Verify every numbered acceptance case in the four feature specs has a
   behavior regression in its owning test target. Fill a coverage table in
   this ticket's Comments using case ID, test name, command, and result.
2. Update `README.md`, `docs/tasks.md`, `docs/analysis-resources.md`,
   `docs/resource-presets.md`, `docs/consumer-compatibility.md`,
   `docs/migration-unreleased.md`, and Unreleased for the actual final behavior.
   Include runnable HTTP listing/extraction, split, and gated expert examples.
   State header-availability timing, preserved content coding, source metadata
   in every part, closed staging handles, and gate/report-selector independence.
3. Generate all new output examples from the real CLI and validate them.
   Keep hand-authored negative/mutation fixtures as tests. Verify generated
   help, completions, and man pages include each flag and the split command.
4. Confirm the v7 archive inventory and the v6/v7 reference-consumer tests.
   Ensure architecture checks and the external consumer still pass. Compile
   existing HTTP/capture fuzz targets after API changes; extend those targets
   to exercise the new bounded core seams, rather than adding an unbounded
   second parser. Add no claim of a fuzz campaign unless it was run.
5. Record the exact final revision/feature profile and validation results.
   Keep fixtures synthetic and offline; native runtime evidence is not needed
   for this batch, which changes no native providers or live workflows.

## Required validation

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked --workspace --no-default-features
python3 scripts/check-architecture.py
python3 scripts/test-output-consumer.py
python3 scripts/test-forwarding-regression.py
python3 scripts/test-native-capture.py
python3 scripts/test-verify-archive.py
python3 scripts/check-external-consumer.py
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
RUSTFLAGS="-D warnings" cargo +nightly-2026-08-28 check --locked --manifest-path fuzz/Cargo.toml --bins
```

The all-feature Linux checks require `libpcap-dev`; use the pinned toolchains.
Also run `generated_documentation_contracts`, `resource_diagnostic_contracts`,
the new feature targets, and the current conformance suite if not already
included in the workspace runs. Avoid repeating passed commands without a
subsequent relevant change. Report an unavailable check honestly.

## Acceptance

- [ ] All feature acceptance IDs map to meaningful passing tests.
- [ ] v6 history is unchanged; real current output/examples/assets agree on v7.
- [ ] Portable execution succeeds with no provider construction or networking.
- [ ] Every new bound has correct resource diagnostics and preset precedence.
- [ ] No source-layout tests, new unsafe code, or accidental core→workflow edge.
- [ ] Documentation describes the final implementation and exact limitations.
- [ ] Applicable CODEOWNERS review is requested with the implementation PR.

## Comments

Implementation test results belong here when implementation is authorized.
No implementation validation is claimed by the specification session.
