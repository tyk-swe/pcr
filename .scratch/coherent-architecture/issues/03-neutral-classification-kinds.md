# 03: Neutral classification kinds

**What to build:** `Kind::Cli` in core's classification becomes a neutral `Kind::Usage`. This affects every crate: core (32 uses, including core fuzz's `cli.fuzz_limit`), netio (`tcp.rs`, `error.rs`, `neighbor/error.rs`, `route/error.rs`, `capture/group.rs`) and packetcraftr. The CLI maps each kind to its exit code and published prefix. Every classification code string, such as `cli.capture_filter`, stays exactly as it is, because codes are frozen. Phase 1. See the spec's "Workspace conventions → Errors" and `CONTEXT.md` **Classification**.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] No library crate references a CLI-named kind.
- [ ] The error-classification contract tests pass unchanged: codes, kinds as published, exit codes.
- [ ] `[Unreleased]` records the Rust rename, and the migration note mentions it.
- [ ] fmt, clippy and the workspace tests pass.
