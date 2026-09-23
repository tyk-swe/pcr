# 05: Duplicate-verification audit

**What to build:** Audit `crates/*/tests/` and in-src `#[cfg(test)]` modules for duplicate verification per AGENTS.md. Delete only clear-cut duplicates; record borderline cases in the spec for maintainer review.

**Blocked by:** None

**Status:** resolved

- [x] Cross-file `#[test]` name audit run; same-named files across crates confirmed as correct layering (core codec vs cli command), not duplication.
- [x] Audit found no clear-cut duplicates; zero deletions.
- [x] Borderline cases recorded in the spec: `service_ports_normalize_and_bound_distinct_values` (http vs dns analysis contracts) and `application_output_budget_counts_only_compact_event_payloads` (cli http vs dns_read).
