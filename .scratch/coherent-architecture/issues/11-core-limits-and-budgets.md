# 11: Limits and budgets in core

**What to build:** Apply the vocabulary in `CONTEXT.md` (**Limit**, **Budget**).
- A configured ceiling is a `…Limits` type with `validate()`, called when the type is constructed or accepted. Only 8 of the 15+ have one today. Add it to the reassembly, capture-file, compression, scope and DHCP limits.
- A running allowance is a `…Budget`.
- DHCP's silent clamp of the caller's limits (`dhcp/mod.rs`) becomes a validation error.
- `pipeline/limits.rs` stops copying the reassembly limits into its own fields and holds them directly.
- `decode::Options` and `build::Options` share their common limit fields through one type.

No shared budget primitive.

Phase 1.

**Blocked by:** 10

**Status:** ready-for-agent

- [ ] Every limits type validates. A limit above its ceiling fails with a classified error and is never lowered silently. Add a DHCP contract test.
- [ ] Types are renamed to match Limit/Budget, and `[Unreleased]` and the migration note list them.
- [ ] fmt, clippy and the workspace tests pass.
