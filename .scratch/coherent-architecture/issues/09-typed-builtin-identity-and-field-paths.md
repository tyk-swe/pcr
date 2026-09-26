# 09: Typed built-in identity and parsed field paths

**What to build:**
- `layer::Id` stays an open identifier so registry extensions keep working.
- Built-in identity comes from the layer's type, not from `BuiltinProtocol::of` matching schema strings.
- Built-in layers are inspected only by typed downcast. `packet::semantics` stops reading string field names (`path.rs`, `vlan.rs`), matching the approach of `analysis/adapter.rs`.
- Field paths become a parsed `FieldPath` type in every API (`Layer::field_path`, `set_field_path`, transform, filter). Strings are parsed only at document and CLI edges.
- `Malformed.intended_protocol` becomes a typed id.

Phase 1.

**Blocked by:** 06, 08

**Status:** resolved

- [x] No built-in identity decision compares schema strings.
- [x] No layer API re-parses a string path per call.
- [x] A custom protocol registered through `registry::Builder` still decodes, builds and reflects. The runtime registry contract tests pass.
- [x] Field-edit contract tests in core and the CLI pass unchanged.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Per decisions.md, the parsed path is the existing `field::Path` (no
  `FieldPath` rename), and `Malformed.intended_protocol` stays text because
  packet/v2 is frozen; malformed-child checks compare that text to built-in
  names.
- `BuiltinProtocol::of`/`identifies` compare type ids from a new `layer`
  column in the catalog (`raw_ip` has none). `from_id`/`from_name` remain for
  registry identifiers where no layer exists (decode traversal, binding
  lookups, and `transform/fields.rs` layouts, left to ticket 12).
- Typed downcasts replace reflective reads in semantics, the response
  matchers, codec validation, live materialization, probe/DNS
  classification, and the netio route planner. The PPPoE and ERSPAN checks
  of the enclosing layer's EtherType field stay reflective on purpose: the
  parent may be a custom link protocol.
- `transform::FieldAssignment`, `fuzz::Target`, and `Template::axis` keep
  their string spellings as document/CLI inputs; each parses once
  (`FieldEdit::compile`, target resolution, `axis`).
- Removed the `protocol::semantics` field-name constants (breaking).
