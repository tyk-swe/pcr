# 01: Execution context module, with the probe runner rebuilt on it

**What to build:** A new crate-level, in-process execution context in the workflow crate (not under `probe`) that owns the operation deadline, the injected clock, pacing between steps, scheduled-delay accounting, per-step execution permits, timeout clipping, and checked stats merging. It enforces the spec's canonical pacing order and canonical step order and maps failures through a `GateErrors`-style error adapter. The probe runner (and so scan and traceroute) drives its pacing and steps through it. See the spec's "Execution context" section.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] The execution context has a small interface: a pacing call that takes a workflow-computed delay, and a step call that takes the step's work (gets the clipped timeout and permit, returns an execution carrying its permit and stats) plus a validation closure.
- [ ] Pacing follows the canonical order: check → start accounting → sleep → deadline and cancellation check → clock failure → account → add scheduled delay.
- [ ] Steps follow the canonical order: check → start accounting → clip → permit → execute → observe interruption → execution failure → permit check → validate → merge stats → surface interruption → account → check.
- [ ] The error adapter maps duration limit, interruption, clock failure, execution failure, invalid evidence (permit mismatch), and stats overflow to the workflow's typed error and keeps the original sources.
- [ ] The probe runner uses the context. Its own pacing and child-timeout plumbing is gone.
- [ ] Tests beside the new module use `RecordingClock` and `Deadline::with_time_source`. They cover a simultaneous clock failure and spent deadline, cancellation during a sleep, scheduled delay added to elapsed stats, timeout clipping, a permit mismatch failing before validation, stats merged before a post-execution interruption surfaces, and stats overflow through the adapter.
- [ ] The probe runner's pacing and child-timeout tests that only re-checked this plumbing are deleted.
- [ ] `[Unreleased]` records the canonical step order change for the probe runner, scan and traceroute: stats are merged before a post-execution interruption surfaces.
- [ ] fmt, clippy (`-D warnings`) and the workspace tests pass.
