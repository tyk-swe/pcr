# 30: Capture and connect scan on the client

**What to build:**
- Live capture becomes `client.capture(request, sink)`, using the composite capture session from ticket 21, and publishes through the event-sink contract. `Control` stays only if early stop can't be expressed as a sink error or request limit; if it stays, a comment says why.
- The TCP connect scan runs through the client, with the shared admission path and the clock, and stays in the `scan::connect` sub-domain.
- `capture::Source` no longer exposes netio's `group::Source` as a public field.
- The capture module takes the fixed roles (it is only `mod.rs` today).

Phase 3.

**Blocked by:** 25

**Status:** ready-for-agent

- [ ] Capture and connect scan contract tests pass.
- [ ] A fake-provider test shows capture honoring the deadline and cancellation.
- [ ] fmt, clippy and the workspace tests pass.
