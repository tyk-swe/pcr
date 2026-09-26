# 38: Move selectors and replay routing out of the CLI

**What to build:**
- These move to core `analysis`/`filter`, beside what they select over: the TLS session/SNI wildcard selector (`tls/mod.rs`), the expert-finding selector (`expert/mod.rs`) and `FrameDecoder`/`FrameSelector` (`filtering.rs`).
- Typed stream selectors no longer turn back into filter text (`"tcp.stream == N"` in `dns_read`, `http` and `tls`).
- Replay interface routing (`SOURCE=IF` / `EXPR=>IF` parsing and conflict resolution in `replay/{mod,selection}.rs`) moves to `packetcraftr::replay` as part of its request.
- Capture ring and rotation (`capture/files.rs`) stays in the CLI.

Phase 4.

**Blocked by:** 31, 35

**Status:** ready-for-agent

- [ ] The CLI has no domain selectors or routing logic.
- [ ] Unit tests move with the code, and the CLI process tests pass unchanged.
- [ ] fmt, clippy and the workspace tests pass.
