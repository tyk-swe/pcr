# 21: Capture group as a composite session

**What to build:** `capture::Group` stays in netio as a composite capture session. It implements `capture::Session` instead of exposing its own `next_record` API and error family (`group::{Error, Cause, Failure}`). Single sessions and groups apply the same filter-size limit; today only groups enforce 64 KiB. `packetcraftr::capture` and the CLI capture command consume groups as sessions. Phase 2.

**Blocked by:** 18

**Status:** ready-for-agent

- [ ] One session contract covers single and grouped capture.
- [ ] A test shows the filter limit is enforced for a single-session request.
- [ ] Capture contract tests pass. `[Unreleased]` records the new single-session filter limit.
- [ ] fmt, clippy and the workspace tests pass.
