# 32: CLI lib holds the application; thin main.rs

**What to build:**
- `packetcraftr-cli`'s lib holds the whole application, and `main.rs` only calls `packetcraftr_cli::main()`.
- Only `output` and the entry point are public; everything else is `pub(crate)`.
- The clap enums in `output` (`contract::Format`, `stats::Table`, `capture::Retention`) move to arguments and convert with `From`. `output` no longer needs clap derives.
- There is one `test_support`, reached by integration tests through the lib instead of `#[path]`, and the lib-side fixture copy is removed.
- `cancellation.rs` uses the cancellation exit-code constant instead of a hard-coded `130`.

Phase 4. This can start after 02; it doesn't depend on the lower phases.

**Blocked by:** 02

**Status:** ready-for-agent

- [ ] `main.rs` is at most a few lines, and there is no `#[path]` test-support include.
- [ ] The CLI process tests pass unchanged.
- [ ] fmt, clippy and the workspace tests pass.
