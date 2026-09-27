# 05: One live-wait ceiling

**What to build:** `deadline::MAX_WAIT` (one hour) replaces `capture::MAX_TIMEOUT` and the private `deadline::MAX_WALL_CLOCK_WAIT`. Every use in netio, packetcraftr, and the CLI moves to it. `[Unreleased]` Breaking and `docs/migration-unreleased.md` record it together with the `SendEvidenceFault` path.

**Blocked by:** 04

**Status:** resolved

- [x] One one-hour constant in netio.
- [x] fmt, clippy, and the workspace tests pass.

## Comments

- The older migration rows that named `capture::MAX_TIMEOUT` as the destination of the workflow duration aliases now name `deadline::MAX_WAIT`, so a reader migrating from beta.3 lands on the final path once.
