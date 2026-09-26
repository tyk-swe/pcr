# 13: Core flat facade

**What to build:** Apply the facade rule to core now that its paths are final.
- Submodules are private and items are re-exported flat. This includes `application::{dns,dhcp,http,ntp,tls}`: TLS's `codec`, `fingerprint`, `model`, `names` and `parse` become private, so the TLS model is `tls::Tls`.
- DNS name decoding keeps one public API (`decode_name` or `name::decompress`, not both), and the `read_u16` primitive becomes private.
- Nothing `#[doc(hidden)]` is used across crates. `layer::raw_layout`, the `reflect_*` family and the matcher helpers become real documented API or move to their user.
- The root `display_via_as_str!` macro either becomes documented public API or is replaced by derives in each crate.

Phase 1.

**Blocked by:** 09, 10, 11, 12

**Status:** ready-for-agent

- [ ] No `#[doc(hidden)]` core item is referenced from another crate.
- [ ] Each item is reachable by exactly one public path.
- [ ] `scripts/check-external-consumer.py` passes.
- [ ] `[Unreleased]` and the migration note list the path changes.
- [ ] fmt, clippy and the workspace tests pass.
