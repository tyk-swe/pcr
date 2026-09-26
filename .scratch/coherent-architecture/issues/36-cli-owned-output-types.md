# 36: CLI-owned output types

**What to build:** Per ADR 0003:
- Output types embed only versioned library documents (`core::document::Packet`). Every other library type serialized today becomes a CLI-owned type with an identical JSON shape. There are about 40 such fields: `analysis::*` in forwarding, netio capture `Stats`/`Id`, `packetcraftr::Stats` in `Envelope`, and others.
- Conversions are `From`/`TryFrom` only, replacing the inherent `from_*`/`complete_from_*`, `Report::new`, free functions and newtypes.
- Commands never build output struct literals; about 35 sites change.
- `stats.rs`'s reverse conversion from output to core is removed.
- `output/fuzz.rs`'s campaign coherence check moves to packetcraftr's fuzz report.

Phase 4.

**Blocked by:** 35

**Status:** ready-for-agent

- [ ] No `output` type has a field whose type comes from another crate, except versioned documents.
- [ ] The v6 aggregate conformance suite serializes real payloads and passes unchanged.
- [ ] fmt, clippy and the workspace tests pass.
