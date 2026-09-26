# 01: Self-named module files across the workspace

**What to build:** Convert all 80 `mod.rs` files to self-named `foo.rs` next to `foo/`, and add `mod_module_files = "deny"` to `[workspace.lints.clippy]` so the style can't drift back. Directories that currently mix both styles (for example `dns/engine.rs` next to `probe/mod.rs`) end up with one style. This is a mechanical `git mv`, with no content changes beyond the paths in `#[path]` attributes and in docs. Phase 0. See the spec's "Workspace conventions".

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] No `mod.rs` remains under `crates/*/src` or `crates/*/tests`, except where Cargo requires one (`tests/common/mod.rs` stays because integration-test helper directories need it; add an `#[allow]` with a reason if the lint flags it).
- [x] `clippy::mod_module_files` is denied workspace-wide.
- [x] `git log --follow` works on moved files (renames only, no content edits in the same commit).
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Clippy does not flag the three `tests/common/mod.rs` files (integration-test
  helper directories), so no `#[allow]` was needed.
- No `#[path]` attribute or `include!` lived in a moved file, and no doc outside
  `.scratch/` named a moved `mod.rs`, so the rename commit has no content edits.
- AGENTS.md now states the self-named module-file rule. No public Rust path
  changed, so there is no changelog or migration entry.
