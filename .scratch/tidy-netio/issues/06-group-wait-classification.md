# 06: Group waits classify like single-session waits

**What to build:** `capture::Group::wait_ready` with a spent deadline reports `Error::CaptureReadiness` (`io.capture_readiness`), and a remainder above `deadline::MAX_WAIT` reports `Error::InvalidCaptureTimeout` (`cli.capture_timeout`), as `NativeCaptureSession` does. One shared helper computes the wait end for both. `tests/capture_group_contracts.rs` covers both; `[Unreleased]` Changed records the codes.

**Blocked by:** 05

**Status:** resolved

- [x] Group and single-session waits publish the same codes for the same conditions.
- [x] fmt, clippy, and the workspace tests pass.

## Comments

- `capture::wait_end` is the shared rule (moved from the native session's private `capture_deadline`); its unit test moved with it, and the group's own `wait_end` is gone.
