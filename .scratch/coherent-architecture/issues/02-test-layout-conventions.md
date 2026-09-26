# 02: Tighten test layout conventions

**What to build:**
- In the CLI, the direct published-schema assertions in `machine_contracts.rs`, `header_rewrite_contracts.rs`, `field_edit_contracts.rs` and `udp_profile_contracts.rs` move into `*_conformance.rs` files. The shared `common::parse_json`/`parse_ndjson` schema guard stays, because it is a guard, not a schema check (already recorded in `CONTEXT.md`).
- In-crate tests are inline `mod tests`, or `<module>/tests.rs` once large. Rename `*_tests.rs` and descriptively named test files (for example `output/stream/{configurable_timeout_tests,publication_budget_tests,failure_boundaries,trace_properties}.rs`) to fit.
- Helpers outside `test_support` move into one: `tls/test_wire.rs` and `output/stream/fixtures.rs`.

Phase 0.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] No schema assertion remains in a `*_contracts.rs` file except through the shared guard.
- [ ] No `*_tests.rs` or descriptively named test modules remain in `src/`.
- [ ] Every in-crate test helper lives in a `test_support` module.
- [ ] Test count is unchanged (move, don't delete), and fmt, clippy and the workspace tests pass.
