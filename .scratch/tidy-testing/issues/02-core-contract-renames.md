# 02: Rename drifted test files in packetcraftr-core

**What to build:** Apply the contract-test suffix to core's drifted files: `field_edits.rs` → `field_edit_contracts.rs`, `forwarding_verify.rs` → `forwarding_verification_contracts.rs`, `reassembly_edges.rs` → `tcp_reassembly_edge_contracts.rs`. Keep `fuzz_smoke.rs` and `protocol_codec_matrix.rs` — accurate non-contract names.

**Blocked by:** None

**Status:** resolved

- [x] Three files renamed via `git mv`.
- [x] `fuzz_smoke.rs`'s `#[path]` reference still resolves.
- [x] fmt, clippy, and workspace tests pass.
