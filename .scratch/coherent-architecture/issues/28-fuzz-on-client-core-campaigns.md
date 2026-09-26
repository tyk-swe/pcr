# 28: Fuzz on the client; core owns campaigns

**What to build:**
- Live fuzz becomes `client.fuzz(request, sink)`, using the shared admission path instead of calling `authorize_operation` directly.
- Its `Request` wraps core's campaign request, replacing `RunInput`, `LiveOptions` and `LiveLimits`. Its `Report` reuses core's `Case`/`CaseOutcome` and adds live evidence by composition.
- The duplicate definitions of `Case`, `CaseOutcome`, `Report`, `Stats` and `Summary` are removed.
- `run_offline_with_events` moves to core, which owns offline campaigns.
- `allow_malformed_live` becomes `allow_permissive_live`; the CLI flag is unchanged.
- The module takes the fixed roles.

Phase 3. See `CONTEXT.md` **Permissive packet**.

**Blocked by:** 25

**Status:** ready-for-agent

- [ ] No fuzz type is defined in both crates.
- [ ] The fuzz contract tests and fuzz output/v6 conformance pass unchanged.
- [ ] `[Unreleased]` and the migration note list the renames.
- [ ] fmt, clippy and the workspace tests pass.
