# 06: Use trait upcasting on Layer

**What to build:** Replace `Layer`'s hand-written `as_any`/`as_any_mut` with trait upcasting to `dyn Any`, which the pinned 1.98 toolchain supports. Keep `clone_box` only if object-safe cloning still needs it, and give the reason in a comment. Update every downcast site in core, packetcraftr and the CLI. Phase 1.

**Blocked by:** 01

**Status:** resolved

- [x] No hand-written `as_any`/`as_any_mut` remains on `Layer` or its implementors.
- [x] `reflective_layer!` no longer generates them.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Call sites use inherent `is`/`downcast_ref`/`downcast_mut` on `dyn Layer`
  (implemented by upcasting `self` to `dyn Any`, like `dyn Error`), rather than
  writing `as &dyn Any` casts, so a `&Box<dyn Layer>` can never be upcast as
  the Box itself. `clone_box` stays with a comment: `Clone` is not object safe.
- No CLI downcast sites existed; `fuzz/` had none either.
