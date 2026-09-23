# 04: Unify in-src test helpers on test_support.rs

**What to build:** Rename `crates/packetcraftr/src/test_fixtures.rs` → `test_support.rs` and `crates/packetcraftr/src/probe/test_fixtures.rs` → `test_support.rs`, updating `mod`/`use` references. `packetcraftr-cli/src/test_support.rs` already conforms.

**Blocked by:** None

**Status:** resolved

- [x] Both `test_fixtures.rs` files renamed; module declarations updated.
- [x] `CONTEXT.md` records `test_support.rs` as the in-src helper name.
- [x] fmt, clippy, and workspace tests pass.
