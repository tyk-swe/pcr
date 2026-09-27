# 04: Capability module shape

**What to build:**
- `route.rs` holds `Provider` and `SystemProvider`; `route/error.rs` holds `Error`; `route/models.rs` keeps `Decision`, `Scope`, `SelectionReason`; `route/provider.rs` is removed and its two test modules merge.
- `capture.rs` splits into `capture/{limits,settings,record}.rs`, keeping `Session`, `Metadata`, `Request`, `Provider`, `SystemProvider` in `capture.rs`.
- `tcp/error.rs` holds `tcp::Error`.
- `SendEvidenceFault` moves to `transmit::SendEvidenceFault` (root re-export removed).
- `interface::Error` implements `Classified` directly.
- Missing module docs are added; `error.rs` and `lib.rs` agree on what `Error` covers.

**Blocked by:** 03

**Status:** resolved

- [x] Public paths unchanged except `transmit::SendEvidenceFault`.
- [x] Classification codes unchanged (`tests/error_contracts.rs`).
- [x] fmt, clippy, and the workspace tests pass.

## Comments

- `interface::discovery_classification` is the one definition of `io.interface_discovery`; `crate::Error::InterfaceDiscovery` reuses it, so `interface::Error` no longer clones itself into `crate::Error` to classify.
- `error::live_io_invariant` is crate-visible so `transmit::SendEvidenceFault` classifies itself where it now lives.
- The `[Unreleased]` and migration entries for `transmit::SendEvidenceFault` land with issue 05's `deadline::MAX_WAIT` entry.
