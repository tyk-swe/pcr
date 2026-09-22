# 02 — `execution::run_workflow`: one driver for the stream-vs-collect dispatch

Status: ready-for-agent

Part of `.scratch/deepen-orchestration-seams/spec.md` (Problem 2, Solution 2).

Add `run_workflow` to the CLI's `execution` composition point: it owns the
NDJSON/aggregate branch, event emission with consistent cancellation, and
the terminal record; commands supply `run` / `run_with_events` /
`on_event` / `into_result` / `render_text` / `complete` hooks. Give
`Providers` a session facet vending the `PolicyAuthorizer` and
`CancellableClock`, and migrate `scan`, `dns`, `traceroute`, `exchange`,
`fuzz`, and connect off their hand-assembled dispatch.

Unit tests use recording fake hooks across all format paths. The dead
`Ndjson => Internal` arms disappear.
