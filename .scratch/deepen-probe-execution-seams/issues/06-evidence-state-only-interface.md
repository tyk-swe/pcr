# 06: EvidenceState and the response selector become the only evidence interface

**What to build:** DNS and fuzz build their evidence through `EvidenceState` and the response selector instead of assembling budgets, undecoded retention and diagnostic logs from the evidence module's low-level helpers. The retention, undecoded-retention and best-candidate helpers become private to the evidence module. DNS's field-for-field copy of the evidence state and its redundant pre-check before candidate selection go away, as do fuzz's separate budget and diagnostic log. See the spec's "Batch evidence" section and user story 6.

**Blocked by:** 02, 03, 04

**Status:** resolved

- [x] The evidence module exports only `EvidenceState`, the response selector and the types they need. The former helper exports are private.
- [x] DNS and fuzz evidence behavior is unchanged: their contract and engine tests pass. (The DNS `max_retained_bytes` double counter is out of scope, so don't fix it here.)
- [x] The evidence module's tests go through `EvidenceState` and the selector, not the private helpers.
- [x] fmt, clippy and the workspace tests pass.
