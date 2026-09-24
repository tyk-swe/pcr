# Honor workflow clock cancellation in pipelined scans

Status: ready-for-human

## Problem

A pipelined scan checks the client cancellation signal but can ignore the
workflow clock signal supplied by an embedder. Cancellation during capture
arming or readiness can therefore be followed by discovery or packet sends.

## Acceptance Criteria

- Workflow clock cancellation is checked before active discovery and before
  every prepared packet transmission, including after capture readiness.
- Cancellation stops subsequent sends, returns the typed interruption, and
  shuts down capture resources.
- Existing budgets and final endpoint and wire-byte authorization remain in
  force.
- Public scan contract tests cover cancellation during arming and after a send.

## References

- Spec: [`../spec.md`](../spec.md), finding 3.

## Comments

- Implemented on [PR #209](https://github.com/tyk-swe/pcr/pull/209); automated
  code review is complete and the fix is ready for human review.
- Follow-up review found readiness ignored an embedder's distinct workflow
  signal: the capture group now observes every armed cancellation source, and
  an observed stop supersedes a provider readiness failure with the typed
  `io.cancelled` interruption.
