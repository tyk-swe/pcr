# 01: Self-named module files across the workspace

**What to build:** Convert all 80 `mod.rs` files to self-named `foo.rs` next to `foo/`, and add `mod_module_files = "deny"` to `[workspace.lints.clippy]` so the style can't drift back. Directories that currently mix both styles (for example `dns/engine.rs` next to `probe/mod.rs`) end up with one style. This is a mechanical `git mv`, with no content changes beyond the paths in `#[path]` attributes and in docs. Phase 0. See the spec's "Workspace conventions".

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] No `mod.rs` remains under `crates/*/src` or `crates/*/tests`, except where Cargo requires one (`tests/common/mod.rs` stays because integration-test helper directories need it; add an `#[allow]` with a reason if the lint flags it).
- [ ] `clippy::mod_module_files` is denied workspace-wide.
- [ ] `git log --follow` works on moved files (renames only, no content edits in the same commit).
- [ ] fmt, clippy and the workspace tests pass.
