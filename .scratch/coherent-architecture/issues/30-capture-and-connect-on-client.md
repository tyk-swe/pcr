# 30: Capture and connect scan on the client

**What to build:**
- Live capture becomes `client.capture(request, sink)`, using the composite capture session from ticket 21, and publishes through the event-sink contract. `Control` stays only if early stop can't be expressed as a sink error or request limit; if it stays, a comment says why.
- The TCP connect scan runs through the client, with the shared admission path and the clock, and stays in the `scan::connect` sub-domain.
- `capture::Source` no longer exposes netio's `group::Source` as a public field.
- The capture module takes the fixed roles (it is only `mod.rs` today).

Phase 3.

**Blocked by:** 25

**Status:** resolved

- [x] Capture and connect scan contract tests pass.
- [x] A fake-provider test shows capture honoring the deadline and cancellation.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- `Control` stays (see its doc): a rotation stop is a success whose before/after accounting no sink error or request limit expresses. Sinks answering `()` continue.
- The selector is part of `capture::Request` (`capture::Selector`) and runs on the capture's thread; the sink runs on the runtime worker.
- A capture read that fails while the client is cancelled reports `Cause::Cancelled` (same `io.cancelled` code).
- Capture now registers a `capture_progress` runtime (a new `--resource-diagnostics` row); connect keeps `scan_connect`, now in every format. Recorded under Changed.
- `connect::Collector::finish` reports a count mismatch as `scan::Error::InvalidEvidence` (`internal.scan_evidence`), to avoid adding a `scan::Error` variant that ticket 27 may also touch.
- `--interface` resolution for capture stays in the CLI (ticket 38).
