# 03 — `admit_operation`: one operation-admission module

Status: ready-for-agent

Part of `.scratch/deepen-orchestration-seams/spec.md` (Problem 3, Solution 3).

Add `admit_operation` to `packetcraftr`'s `target` area: it owns the
resolve → authorize targets → empty/family gate → count → worst-case
duration → `approve_operation` ordering, taking the workflow's budget
arithmetic as a closure. Migrate the admission sequences in `scan`,
`traceroute`, connect, `dns`, and `fuzz`.

Unit tests beside `target` use a recording fake authorizer to assert call
ordering and gate short-circuiting. Engines keep only budget math.
