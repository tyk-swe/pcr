# 36: CLI-owned output types

**What to build:** Per ADR 0003:
- Output types embed only versioned library documents (`core::document::Packet`). Every other library type serialized today becomes a CLI-owned type with an identical JSON shape. There are about 40 such fields: `analysis::*` in forwarding, netio capture `Stats`/`Id`, `packetcraftr::Stats` in `Envelope`, and others.
- Conversions are `From`/`TryFrom` only, replacing the inherent `from_*`/`complete_from_*`, `Report::new`, free functions and newtypes.
- Commands never build output struct literals; about 35 sites change.
- `stats.rs`'s reverse conversion from output to core is removed.
- `output/fuzz.rs`'s campaign coherence check moves to packetcraftr's fuzz report.

Phase 4.

**Blocked by:** 35

**Status:** resolved

- [x] No `output` type has a field whose type comes from another crate, except versioned documents.
- [x] The v6 aggregate conformance suite serializes real payloads and passes unchanged.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- `FieldValue` counts as part of the versioned packet document: packet/v2
  layers embed it and the v6 schema's `packetDocument` references the same
  `fieldValue` definition, so fuzz, verify-forwarding, projection, and dns-read
  keep it.
- Multi-input conversions take tuples (`From<(A, B, …)>`); conversions that
  also yield diagnostics/stats target `envelope::Published<T>`, since a tuple
  target cannot implement `From`.
- Foreign `non_exhaustive` enums (`FieldKind`, `EncapsulationIdentifier`,
  `replay::Timing`) convert with `TryFrom`, failing with the new
  `contract::Error::Unpublished` classified as the existing `internal.error`
  (no new code; unreachable today). An unpublished `Coordinate` is omitted.
- The coherence check now runs in full before case conversion, so an incoherent
  campaign with an out-of-range timestamp reports incoherence first.
- Left as is: capture file rotation (`commands/capture/files.rs`) keeps its
  CLI-owned file report records as state; `resources.rs` builds resource
  settings; text renderers still read some library reports (not in this
  ticket's list).
- Proof: an instrumented run of the aggregate and NDJSON conformance suites and
  the CLI unit tests dumped every serialized record before and after
  (155 + 21 records); they are byte-identical apart from wall-clock fields.
