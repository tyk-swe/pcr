# 03: Neutral classification kinds

**What to build:** `Kind::Cli` in core's classification becomes a neutral `Kind::Usage`. This affects every crate: core (32 uses, including core fuzz's `cli.fuzz_limit`), netio (`tcp.rs`, `error.rs`, `neighbor/error.rs`, `route/error.rs`, `capture/group.rs`) and packetcraftr. The CLI maps each kind to its exit code and published prefix. Every classification code string, such as `cli.capture_filter`, stays exactly as it is, because codes are frozen. Phase 1. See the spec's "Workspace conventions → Errors" and `CONTEXT.md` **Classification**.

**Blocked by:** 01

**Status:** resolved

- [x] No library crate references a CLI-named kind.
- [x] The error-classification contract tests pass unchanged: codes, kinds as published, exit codes.
- [x] `[Unreleased]` records the Rust rename, and the migration note mentions it.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- The CLI output envelope serialized core's `Kind` directly, so the rename
  needed a CLI-owned published kind: `output::envelope::ErrorKind`
  (`From<Kind>`, `Usage` -> `"cli"`), also used by the root `--help`
  exit-code table. This changes the type of the CLI crate's public
  `envelope::Error.kind`; recorded as breaking. Output, schemas, and examples
  are unchanged.
- Core `Kind::Usage` serializes and displays as `"usage"`; nothing in the
  published contract serializes core's `Kind` any more.
