# 21: Capture group as a composite session

**What to build:** `capture::Group` stays in netio as a composite capture session. It implements `capture::Session` instead of exposing its own `next_record` API and error family (`group::{Error, Cause, Failure}`). Single sessions and groups apply the same filter-size limit; today only groups enforce 64 KiB. `packetcraftr::capture` and the CLI capture command consume groups as sessions. Phase 2.

**Blocked by:** 18

**Status:** resolved

- [x] One session contract covers single and grouped capture.
- [x] A test shows the filter limit is enforced for a single-session request.
- [x] Capture contract tests pass. `[Unreleased]` records the new single-session filter limit.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Per decision C8: `Session` gains `source_count`/`source_metadata` (single-source defaults) and `Captured` a public `source` field. Group errors fold into `packetcraftr_netio::Error` (`InvalidCaptureGroup`, `CaptureSource`, `CaptureSourceContract`, `CaptureGroupState`, and `CaptureCleanup` for several cleanup failures), keeping `cli.capture_group`/`internal.capture_group`.
- To keep `snapshot()` readable after an arming failure, arming has two steps: `Group::new(&request, cancellation)` validates, then `group.arm(&provider)`. A group that admitted no source reports placeholder metadata (no interface, snap length 0) from `Session::metadata`. Cleanup failures come from the following `shutdown()`, not inside the primary error.
- The group module is private. Its types are flat, following the facade rule: `capture::{Group, GroupRequest, Source, Phase, MAX_SOURCES}`.
- The filter limit is `capture::MAX_FILTER_BYTES`, and it fails with the new `Error::CaptureFilterTooLong` (`cli.capture_filter`). A group's oversized filter now reports `cli.capture_filter` instead of `cli.capture_group`, so both paths classify it the same way (recorded under Changed). The error-table contract requires a remediation for every netio variant, so the group codes now publish one.
- Group source failure messages no longer repeat the source failure, which moves to `causes` (spec error convention).
- Wait and deadline signatures are unchanged (ticket 19).

