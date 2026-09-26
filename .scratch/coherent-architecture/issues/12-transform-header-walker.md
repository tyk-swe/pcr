# 12: Codec-first transforms with one shared header walker

**What to build:** Per ADR 0004:
- `transform::rewrite` and `transform::fragment` use codecs wherever the decode/re-encode round trip is byte-faithful.
- Where it can't be guaranteed (malformed or unknown bytes, non-canonical encodings), they edit bytes through one shared link/VLAN/IP header walker. It replaces `ethernet_payload` and the per-module parsing in `rewrite.rs` and `fragment.rs`, and the neighbor code reuses it in ticket 16.
- Each remaining byte-level edit says which faithfulness gap it avoids.

Phase 1.

**Blocked by:** 05, 08

**Status:** resolved

- [x] There is one header walker. `transform::fields`, `rewrite` and `fragment` share it or the codecs.
- [x] Rewrite and fragment contract tests pass unchanged. Add a test where a malformed trailer survives a rewrite byte for byte.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- The walker is `packetcraftr_core::protocol::headers` (protocols layer):
  `LinkHeader`, `EthernetHeader`, `IpHeader`, `Ipv4Header`, `Ipv6Header`,
  `Ipv6Extension`, option iterators, and a typed `headers::Error`, wrapped as
  `transform::Error::Header` with the existing classification codes.
- No transform re-encodes through codecs: rewrite and fragment take captured
  frames, whose round trip is not guaranteed faithful, so both edit bytes via
  the walker, and field edits keep locating fields through the decoded layout
  (codecs) and use the walker for checksum-coverage checks. The transform
  module docs and each byte-level edit say why.
- A temporary 40,000-case differential property test against the old
  implementations (not committed) found identical output bytes and Ok/Err
  outcomes. The only difference is that malformed option or extension-header
  lengths the old code never read now report `packet.transform_input`
  instead of `packet.transform_unsupported` (CHANGELOG Changed).
