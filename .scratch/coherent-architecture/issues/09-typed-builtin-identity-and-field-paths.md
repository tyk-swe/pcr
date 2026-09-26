# 09: Typed built-in identity and parsed field paths

**What to build:**
- `layer::Id` stays an open identifier so registry extensions keep working.
- Built-in identity comes from the layer's type, not from `BuiltinProtocol::of` matching schema strings.
- Built-in layers are inspected only by typed downcast. `packet::semantics` stops reading string field names (`path.rs`, `vlan.rs`), matching the approach of `analysis/adapter.rs`.
- Field paths become a parsed `FieldPath` type in every API (`Layer::field_path`, `set_field_path`, transform, filter). Strings are parsed only at document and CLI edges.
- `Malformed.intended_protocol` becomes a typed id.

Phase 1.

**Blocked by:** 06, 08

**Status:** ready-for-agent

- [ ] No built-in identity decision compares schema strings.
- [ ] No layer API re-parses a string path per call.
- [ ] A custom protocol registered through `registry::Builder` still decodes, builds and reflects. The runtime registry contract tests pass.
- [ ] Field-edit contract tests in core and the CLI pass unchanged.
- [ ] fmt, clippy and the workspace tests pass.
