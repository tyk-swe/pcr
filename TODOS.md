# Deferred work

Items left out of a shipped change on purpose. Candidates, not commitments.

## TLS (deferred from the `tls` command)

- `stats --tls` section alongside `protocols` and `conversations`.
- Expert codes: `tls.malformed`, `tls.handshake_gap`,
  `tls.deprecated_version`, `tls.compression_negotiated`, `tls.fatal_alert`.
- Content-sniffed dispatch, so TLS on an unbound TCP port dissects without
  `--tls-port`.
- Certificate summary (subject, issuer, validity, SANs) from the TLS 1.2 chain.
- `tls diff`: compare two captures by fingerprint and parameters.
- Active prober: send a ClientHello, report the server's selection.
- JA4S and the rest of JA4+.
- QUIC and DTLS handshakes (`tls` only counts UDP/443 frames today).
- `StreamCollector` trait shared by `follow`, `expert`, and `tls`; wait for a
  fourth collector to show the shape.
- `--columns` field selection for text output (`tshark -T fields -e`).
- Partial hello reporting: keep what parsed before a failing extension. One bad
  optional extension currently marks the whole hello `malformed` and hides the
  fingerprint, and a first message shaped like a ServerHello poisons the
  stream's role election.
- Hot-path allocation, benchmark first: borrow record bodies in the per-frame
  codec instead of `Bytes::copy_from_slice` per record; expose TCP flags on
  `FrameRecord` so collectors stop re-walking the layer stack.
- Typed direction enum in `analysis::tls::session` instead of the `usize` key.
- A JA3 MD5 / JA4 vector from a real full ClientHello, so the fingerprints are
  checked against something other than our own builder.

## Review follow-ups (2026-08-26 recovery pass)

Need a decision, not a mechanical edit.

- `authorization::Operation` derives `Default` and every call site ends in
  `..Operation::default()`, so a forgotten field takes the permissive value.
  Either document per-field ownership and assert on unexpected combinations,
  or split into per-shape request types so an unread field fails to compile.
- The narrowed format enums in `commands/format.rs` have no conversions; four
  call sites hand-write the re-narrowing match. Have `narrowed_format!`
  generate it.
- The deny sweep skips panicking range APIs (`Vec::drain`, `slice::chunks`,
  `Bytes::slice`). `reassembly/tcp/state.rs` `drain(..old_start)` and
  `scan/plan.rs` `chunks(batch_size)` rely on a `debug_assert!` or upstream
  validation. Guard them or lint them.

## Distribution

- Crates are `publish = false`; install is from a release archive or source.
  Publishing the AGPL crates is an owner decision.

## packet/v2 follow-ups (0.7, from the 2026-08-26 eng review)

Design: `docs/designs/packet-v2-contract.md`.

### Structured list values

**What:** A nested-map `FieldValue` variant plus `element` schema so a list can hold sub-fields (TCP options, IPv6 extension-header entries).
**Why:** Options are opaque bytes today; a fixture cannot say `mss: 1460` and the schema cannot describe option sub-fields.
**Context:** Deferred because no registry field produces a list of structs. Ten exhaustive `FieldValue` match sites plus the expression, filter, and fuzz engines change. Additive to v2 since unknown value forms are rejected. Start at `field.rs` and the first protocol that reflects structured options.
**Effort:** L **Priority:** P2 **Depends on:** packet/v2 shipped.

### Per-field derived verification

**What:** A per-layer hook reporting what `auto` would produce for one field, so the emitter keeps only the mismatching derived field explicit.
**Why:** The 0.6 minimizer is whole-packet rebuild-and-compare; one bad checksum makes every derived field in that packet explicit.
**Context:** Chosen against in favour of the builder-as-oracle. Touches all 37 `reflective_layer!` sites and adds a second derivation path that must be tested against `encode`. Start at `layer/reflection.rs` and `protocol/support.rs` `resolve_u16`. Revisit only if all-or-nothing minimization is a complaint.
**Effort:** L **Priority:** P3 **Depends on:** packet/v2 shipped.

### Property-based round-trip generation

**What:** Per-protocol generators feeding `bytes → dissect → v2 → build → bytes`.
**Why:** The 0.6 corpus (builtin wire images, captures, end-to-end fixtures, seeded fuzz variants) is bounded by fixtures.
**Context:** A `proptest` dependency goes through `cargo deny`; 37 generators; tune case counts under nextest's 15 s slow-timeout. Start from `tests/protocol_codec_matrix.rs` and the fuzz mutation value generators.
**Effort:** M **Priority:** P3 **Depends on:** `document_v2_round_trip.rs`.

### Document as the primitive: `diff`, `--set`, `test`

**What:** Semantic diff of two v2 documents by field path, a `--set proto#N.field=value` patch on any document, and a `test cases/*.yaml` runner checking expected bytes and dissection.
**Why:** One primitive replaces `Template` and ad-hoc fuzz axes; no tool in the space has a semantic packet diff.
**Context:** Office-hours approach C, deferred to 0.7. `--set` reuses `filter::path` and the shared coercer from 0.6.
**Effort:** XL **Priority:** P2 **Depends on:** packet/v2, `field::coerce`, `--columns`.

### `--filter` on every capture-reading command

**What:** The display-filter flag `read` has, on `stats`, `expert`, `follow`, and `tls`.
**Why:** tshark parity.
**Context:** Pulled out of 0.6 as unrelated to the contract break. Each collector needs a pre-filter hook; a per-frame filter can split a stream in `tls` and `follow`, so define that interaction first. Start at `commands/offline_analysis.rs` and the `StreamCollector` item above.
**Effort:** M **Priority:** P3 **Depends on:** none.

### Registry-driven output/v2 schema emitter

**What:** `schema emit --contract output/v2` generated from typed output records, replacing the hand-maintained 119 KB file.
**Why:** packet/v2 is generated in 0.6; output/v2 stays hand-edited, so the two contracts drift by different mechanisms.
**Context:** Office-hours approach B, surfaced again by /autoplan on 2026-08-26. Needs shared output record types (frame, stream, finding, session) defined once; that design does not exist. Start after 0.6 from `crates/packetcraftr/src/output/`.
**Effort:** L **Priority:** P3 **Depends on:** output/v2 shipped.
