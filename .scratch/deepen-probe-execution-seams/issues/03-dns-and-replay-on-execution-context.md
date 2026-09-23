# 03: DNS, the DNS batch runner and replay pace and execute through the execution context

**What to build:** DNS (retry delay), the DNS batch runner (max of previous and current delay) and replay (source-timing delay) drive pacing, and DNS its execution step, through the execution context from ticket 01, each with an error adapter. DNS retry/TCP fallback and the batch runner's mapping to unattempted vs failed questions stay in DNS. See the spec's "Execution context" section and user story 18.

**Blocked by:** 01

**Status:** resolved

- [x] The copied pacing sequences in dns, the DNS batch runner and replay are gone, and each uses the context with its own delay input.
- [x] DNS's execution step uses the context's step. The merge-before-surfacing rule is kept, and its rationale lives in the context.
- [x] Unattempted vs failed classification and retry/TCP fallback behave as before: the DNS batch, cancellation and TCP contract tests pass, and so do the replay tests.
- [x] Unit tests that only re-checked the copied pacing plumbing are deleted.
- [x] `[Unreleased]` records the canonical pacing order for dns, dns batch and replay.
- [x] fmt, clippy and the workspace tests pass.
