# 06: Use trait upcasting on Layer

**What to build:** Replace `Layer`'s hand-written `as_any`/`as_any_mut` with trait upcasting to `dyn Any`, which the pinned 1.98 toolchain supports. Keep `clone_box` only if object-safe cloning still needs it, and give the reason in a comment. Update every downcast site in core, packetcraftr and the CLI. Phase 1.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] No hand-written `as_any`/`as_any_mut` remains on `Layer` or its implementors.
- [ ] `reflective_layer!` no longer generates them.
- [ ] fmt, clippy and the workspace tests pass.
