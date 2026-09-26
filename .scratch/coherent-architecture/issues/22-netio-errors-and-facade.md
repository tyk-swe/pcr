# 22: netio errors and public surface

**What to build:** Apply the workspace error convention and facade rule to netio.
- One representation for "unsupported" (today both `SystemError::Unsupported` and `Error::Unsupported`, mapped in `dispatch.rs`).
- One way of storing type-erased sources (today `Arc`, `Box` and `io::Error` are mixed).
- No dropped sources: `neighbor/options.rs` is gone by now; npcap sets `source: None`.
- `tcp::ConnectError` and `io::Result` fold into `tcp::Error`.
- Message-string classification in `pcap_common.rs` stays only where libpcap offers nothing else, with a comment.
- Facade: no types that appear in public fields without being reachable. Public fields use core's `packet::link::{MacAddress, VlanTag}` directly. Remove the `#[forbid(unsafe_code)]` on the `PacketIo` impl block.
- Decide whether pcap-specific `NativeSettings`/`TimestampSource`/`TimestampType` stay public capture API, and document the decision in the module.

Phase 2.

**Blocked by:** 20, 21

**Status:** ready-for-agent

- [ ] Every public netio error implements `Classified` and keeps its source.
- [ ] Classification codes are unchanged, and the error-classification contract tests pass.
- [ ] `[Unreleased]` and the migration note list the error type changes.
- [ ] fmt, clippy and the workspace tests pass.
