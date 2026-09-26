# 08: One protocol shape and grouping by layer

**What to build:**
- **Shape:** each protocol is `<proto>.rs` holding the model, `reflective_layer!` and codec, and grows into `<proto>/` with `codec`/`reflection`/`model` submodules only when large. Bring DNS (layer and codec in `dns.rs`, helpers in `dns/`), DHCP (the layer in `v4|v6/reflection.rs`, a macro in `codec.rs`) and TLS (layer and codec in `codec.rs`, types in `model.rs`) into this shape.
- **Errors:** wire APIs return the protocol's own `Error`. DNS stops returning `DecodeError` in one direction and `codec::Error` in the other, and HTTP's `head::Error` folds into `http::Error`.
- **Grouping by layer:** `gre` → tunnel, `icmp` → network, IPv6 extension headers under `network/ipv6`, and `protocol/builtin/{registry,filter}.rs` renamed so they don't shadow `crate::{registry,filter}`.
- **Field visibility** stays as it is per protocol.

Phase 1.

**Blocked by:** 07

**Status:** ready-for-agent

- [ ] Every protocol follows the shape, and every protocol module sits in its layer group.
- [ ] The protocol codec matrix and dissection contract tests pass with only import changes.
- [ ] `[Unreleased]` and the migration note list moved paths and error types.
- [ ] fmt, clippy and the workspace tests pass.
