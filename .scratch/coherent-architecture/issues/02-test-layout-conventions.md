# 02: Tighten test layout conventions

**What to build:**
- In the CLI, the direct published-schema assertions in `machine_contracts.rs`, `header_rewrite_contracts.rs`, `field_edit_contracts.rs` and `udp_profile_contracts.rs` move into `*_conformance.rs` files. The shared `common::parse_json`/`parse_ndjson` schema guard stays, because it is a guard, not a schema check (already recorded in `CONTEXT.md`).
- In-crate tests are inline `mod tests`, or `<module>/tests.rs` once large. Rename `*_tests.rs` and descriptively named test files (for example `output/stream/{configurable_timeout_tests,publication_budget_tests,failure_boundaries,trace_properties}.rs`) to fit.
- Helpers outside `test_support` move into one: `tls/test_wire.rs` and `output/stream/fixtures.rs`.

Phase 0.

**Blocked by:** 01

**Status:** resolved

- [x] No schema assertion remains in a `*_contracts.rs` file except through the shared guard.
- [x] No `*_tests.rs` or descriptively named test modules remain in `src/`.
- [x] Every in-crate test helper lives in a `test_support` module.
- [x] Test count is unchanged (move, don't delete), and fmt, clippy and the workspace tests pass.

## Comments

- CLI schema checks moved to the new `published_schema_conformance.rs`; the
  every-output-example check joined `published_example_matrix.rs`. Four tests
  mixed a CLI behavior check with a schema check, so each was split: the test
  count rises by those four halves (1679 -> 1683), and nothing was deleted.
- Beyond the CLI, `packetcraftr/tests/packet_document_contracts.rs` (schema and
  loader checks of the published packet examples) became
  `packet_document_conformance.rs`.
- Beyond the named files, descriptively named inline test modules in core,
  netio and packetcraftr merged into `mod tests`, the CLI execution tests'
  nested `workflow` module was flattened, and other helpers moved to
  `test_support`: packetcraftr's sent-packet fixtures (from `evidence.rs`),
  netio's `error::testing`, and core's TCP page work counters (`pages::work`).
- `output/stream/test_support.rs` is local to the CLI library; the binary's
  `src/test_support.rs` stays separate until the lib/binary merge.
- `PreparedPacket::fixture` and test-only inspection accessors stay on their
  types, because they need private fields.
