# 12: Codec-first transforms with one shared header walker

**What to build:** Per ADR 0004:
- `transform::rewrite` and `transform::fragment` use codecs wherever the decode/re-encode round trip is byte-faithful.
- Where it can't be guaranteed (malformed or unknown bytes, non-canonical encodings), they edit bytes through one shared link/VLAN/IP header walker. It replaces `ethernet_payload` and the per-module parsing in `rewrite.rs` and `fragment.rs`, and the neighbor code reuses it in ticket 16.
- Each remaining byte-level edit says which faithfulness gap it avoids.

Phase 1.

**Blocked by:** 05, 08

**Status:** ready-for-agent

- [ ] There is one header walker. `transform::fields`, `rewrite` and `fragment` share it or the codecs.
- [ ] Rewrite and fragment contract tests pass unchanged. Add a test where a malformed trailer survives a rewrite byte for byte.
- [ ] fmt, clippy and the workspace tests pass.
