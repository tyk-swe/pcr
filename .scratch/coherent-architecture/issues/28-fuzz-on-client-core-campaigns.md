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

**Status:** resolved

- [x] No fuzz type is defined in both crates.
- [x] The fuzz contract tests and fuzz output/v6 conformance pass unchanged.
- [x] `[Unreleased]` and the migration note list the renames.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Decision 6 overrides "`run_offline_with_events` moves to core": it is deleted.
  Core already runs offline campaigns with events (`fuzz::run_observed`); the
  CLI publishes them through its own `progress::Worker`.
- Decision 7: the live outcome is `fuzz::Outcome { Response, Timeout }`. The
  live case is not a second `Case`: `fuzz::Trial { case: core Case, evidence:
  Option<fuzz::Evidence> }` (rejected cases have no evidence). `fuzz::Report`
  is `{ seed, first_case, campaign: core Stats, stats: packetcraftr::Stats }`;
  `fuzz::Aggregate` adds `trials`. The evidence bounds are plain request
  fields, so no `fuzz::Limits` shadows core's.
- `Error` and `Request` exist in both crates by design (the live request wraps
  core's; the live error wraps core's as `Error::Campaign`).
- `Totals`/`IncoherentReport` moved to core (campaign coherence);
  packetcraftr adds `TryFrom<&fuzz::Aggregate> for Totals`.
  `Collector::finish` is infallible; coherence has one owner (`Totals`).
- The engine still takes an `Authorizer`; the client passes its
  `admission()`, so live fuzz no longer builds its own `PolicyAuthorizer`.
- Resources report: the client's runtime is named `fuzz_progress` (decision
  c), so live fuzz shows one row instead of an idle `client_progress` row plus
  an NDJSON `fuzz_progress` row. Recorded under Changed.
- The authorization-time cancellation case moved from the IT to an in-crate
  test: a real client's admission cannot cancel.
