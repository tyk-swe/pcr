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

**Status:** resolved

- [x] Every public netio error implements `Classified` and keeps its source.
- [x] Classification codes are unchanged, and the error-classification contract tests pass.
- [x] `[Unreleased]` and the migration note list the error type changes.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- C11: the shared representation is the public struct `netio::Unsupported { capability: NativeCapability, message, source }`,
  carried by `netio::Error`, `route::SystemError`, and `interface::Error` (`Unsupported(Unsupported)`, transparent).
  `NativeCapability::{Route, InterfaceEnumeration, Capture, Transmission(Mode)}`; `Route` publishes `capability.route`, the
  rest `capability.unsupported`. Messages unchanged. packetcraftr's replay reports "route adapter cannot select a replay
  route" as `Transmission(Layer3)` so it keeps `capability.unsupported`.
- Sources: `SystemFault` is removed; everything type-erased is core `error::Source` (also packetcraftr `dns::tcp::Error`).
  Typed `io::Error` stays typed in `tcp::Error`.
- `tcp::Error::Socket(io::Error)` is a new variant with a new code, `io.tcp_connect`: before, a socket failure was never a
  classified error. Every existing code is unchanged. A connection stopped before its provider ran is now
  `DeadlineExceeded`/`Cancelled`; the connect scan still publishes kind `TimedOut`/`Interrupted`, with a new message.
- Dropped sources: pcap-API failures keep a crate-private `Diagnostic` (status + error-buffer text), and the text moved
  from message to causes. Remaining `source: None` sites are PacketcraftR checks (invariants, limits, panics).
  `UnsupportedCaptureSetting`, `InvalidCaptureFilter`, and `CaptureFilterInstallation` have no source field and keep the
  backend text in their message.
- Facade: `#![warn(unnameable_types)]` found nothing on Linux, Windows, or macOS. The only crate-private re-export in
  public fields was `MacAddress` (core path `packet::MacAddress` after ticket 13, not `packet::link::`).
- Also done: `SendEvidenceFault` implements `Classified`, and messages that repeated their source no longer do.
