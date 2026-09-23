# Tidy testing: naming vocabulary, helper convergence, duplicate audit

Status: resolved

## Problem Statement

The test tree has drifted from its own conventions:

1. **File naming.** `crates/*/tests/` mostly uses `*_contracts.rs` for
   public-behavior regressions, but ~25 files omit the suffix
   (`dhcp.rs`, `field_edits.rs`, `reassembly_edges.rs`, `http.rs`, …).
   Genuine non-contract categories already exist — `*_conformance.rs`,
   `*_matrix.rs`, `*_smoke.rs`, `native_isolated.rs` — but the drift
   files are plain contracts with the suffix missing.
2. **Helper locations.** Integration helpers live under `tests/common/`
   in `packetcraftr-core` but `tests/support/` in `packetcraftr` and
   `packetcraftr-cli`. In-src test helpers are `src/test_fixtures.rs`
   (packetcraftr, twice) and `src/test_support.rs` (cli).
3. **Duplicate verification.** AGENTS.md says to avoid it, but no audit
   has checked whether it exists.

## Solution

1. Adopt the small suffix vocabulary recorded in `CONTEXT.md`:
   `*_contracts.rs` for public-behavior regressions, keeping
   `*_conformance.rs`, `*_matrix.rs`, `*_smoke.rs`, and
   `native_isolated.rs` where accurate. Drift files are renamed;
   `git mv` preserves history. No same-domain file merging — the
   file-per-area granularity is intentional. Same-named files across
   crates (`field_edits` in core and cli) are correct layering, not
   duplication: core tests codec behavior, cli tests the command.
2. One helper name per layer: `tests/common/` for integration helpers
   (rename the two `tests/support/` directories, update `mod support;`
   imports), `src/test_support.rs` for in-crate helpers (rename
   packetcraftr's two `test_fixtures.rs`; cli already conforms).
3. Duplicate audit: delete only clear-cut duplicates. **Audit result:
   none found.** Borderline cases kept for maintainer review:
   - `service_ports_normalize_and_bound_distinct_values` exists in both
     `http_analysis_contracts.rs` and `dns_analysis_contracts.rs`. The
     port-normalization policy is shared, but each test asserts its own
     collector's error field (`http_ports` vs `dns_ports`) and
     constructor signature.
   - `application_output_budget_counts_only_compact_event_payloads`
     exists in both cli `http.rs` and `dns_read.rs`. The budget
     mechanism is shared, but each command wires its own event
     collections, which could individually miswire.

Unit-test placement (inline `mod tests` vs sibling `tests.rs`) is left
alone: AGENTS.md's "beside their owner" admits both, and the split is
size-based.

## Implementation Decisions

- Branch `tyk/tidy-testing`; focused conventional commits per issue.
- No behavior changes; no CHANGELOG entry (not user-visible).
- Cross-crate alignment where the same thing has two names:
  `merge_captures.rs` → `capture_merge_contracts.rs` (core's name), and
  core `forwarding_verify.rs` + cli `verify_forwarding.rs` →
  `forwarding_verification_contracts.rs` in both.
- `reassembly_edges.rs` → `tcp_reassembly_edge_contracts.rs`: it covers
  TCP reassembly edges, distinct from `ip_reassembly_contracts.rs`.
- Gate: `cargo fmt --all -- --check`,
  `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`,
  `cargo test --locked --workspace --all-features` (green at baseline).
