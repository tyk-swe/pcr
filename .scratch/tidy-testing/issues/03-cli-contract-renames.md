# 03: Rename drifted test files in packetcraftr-cli

**What to build:** Apply the contract-test suffix to cli's drifted files, aligning cross-crate names where the same behavior has two names (`merge_captures.rs` → `capture_merge_contracts.rs`, `verify_forwarding.rs` → `forwarding_verification_contracts.rs`). Full map in the spec. Keep `published_example_matrix.rs` — accurate matrix name.

**Blocked by:** None

**Status:** resolved

- [x] All 23 drifted files renamed per the spec map.
- [x] `mod support;` references already updated by issue 01.
- [x] fmt, clippy, and workspace tests pass.
