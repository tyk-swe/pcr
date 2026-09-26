# 32: CLI lib holds the application; thin main.rs

**What to build:**
- `packetcraftr-cli`'s lib holds the whole application, and `main.rs` only calls `packetcraftr_cli::main()`.
- Only `output` and the entry point are public; everything else is `pub(crate)`.
- The clap enums in `output` (`contract::Format`, `stats::Table`, `capture::Retention`) move to arguments and convert with `From`. `output` no longer needs clap derives.
- There is one `test_support`, reached by integration tests through the lib instead of `#[path]`, and the lib-side fixture copy is removed.
- `cancellation.rs` uses the cancellation exit-code constant instead of a hard-coded `130`.

Phase 4. This can start after 02; it doesn't depend on the lower phases.

**Blocked by:** 02

**Status:** resolved

- [x] `main.rs` is at most a few lines, and there is no `#[path]` test-support include.
- [x] The CLI process tests pass unchanged.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Integration tests reach `test_support` through a `test-support` Cargo
  feature, enabled by a self dev-dependency (`packetcraftr-cli` is now a
  `default-features = false` workspace dependency). An integration-test
  build can't see `cfg(test)`, so a gate like this is needed.
- `jsonschema` stays a dev-dependency. It is not an optional feature
  dependency because `--all-features` release builds and `cargo deny` would
  pick it up. So `schema_validator` is `#[cfg(test)]` in `test_support`, and
  `tests/common` builds its own validator over the shared `output_schema()`.
- The library now documents private items, so four clap help doc comments
  that rustdoc misreads as markup (`[1,64]`, `<field>`, `TYPE<n>`,
  `[:DEI]`) carry field-level `#[allow(rustdoc::...)]`. The help text is
  unchanged.
- The new argument enums are `cli::Format`, `commands::stats::arguments::Table`,
  and `commands::capture::arguments::Retention`.
