# 10: CLI send and exchange share one pre-discovery preparation step

**What to build:** In the CLI crate, `send` and `exchange` share one pre-discovery preparation step: validate options before recipe parsing, parse the recipe, build the template, validate policy once, authorize the budget count, authorize the expanded destinations, and prepare the packet route. Each command supplies only its budget count: `send` counts repeats through its set options, and `exchange` uses the expansion length. The CLI's `system/` providers stay as they are. See the spec's "Staged preparation → CLI" decision and user stories 27–29.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] The eight-step copy is gone from both commands, and policy validation runs once per command.
- [x] Unit tests on the shared step with an invalid option and an invalid recipe show that options fail first for both commands.
- [x] The CLI process contract tests and the machine-output schemas and examples are unchanged and pass.
- [x] If option-before-recipe ordering changes a user-visible error for either command, it is recorded under `[Unreleased]`.
- [x] fmt, clippy and the workspace tests pass.
