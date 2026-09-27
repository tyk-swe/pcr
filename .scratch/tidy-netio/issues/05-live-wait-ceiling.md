# 05: One live-wait ceiling

**What to build:** `deadline::MAX_WAIT` (one hour) replaces `capture::MAX_TIMEOUT` and the private `deadline::MAX_WALL_CLOCK_WAIT`. Every use in netio, packetcraftr, and the CLI moves to it. `[Unreleased]` Breaking and `docs/migration-unreleased.md` record it together with the `SendEvidenceFault` path.

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] One one-hour constant in netio.
- [ ] fmt, clippy, and the workspace tests pass.
