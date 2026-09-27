# 08: One protocol shape and grouping by layer

**What to build:**
- **Shape:** each protocol is `<proto>.rs` holding the model, `reflective_layer!` and codec, and grows into `<proto>/` with `codec`/`reflection`/`model` submodules only when large. Bring DNS (layer and codec in `dns.rs`, helpers in `dns/`), DHCP (the layer in `v4|v6/reflection.rs`, a macro in `codec.rs`) and TLS (layer and codec in `codec.rs`, types in `model.rs`) into this shape.
- **Errors:** wire APIs return the protocol's own `Error`. DNS stops returning `DecodeError` in one direction and `codec::Error` in the other, and HTTP's `head::Error` folds into `http::Error`.
- **Grouping by layer:** `gre` → tunnel, `icmp` → network, IPv6 extension headers under `network/ipv6`, and `protocol/builtin/{registry,filter}.rs` renamed so they don't shadow `crate::{registry,filter}`.
- **Field visibility** stays as it is per protocol.

Phase 1.

**Blocked by:** 07

**Status:** resolved

- [x] Every protocol follows the shape, and every protocol module sits in its layer group.
- [x] The protocol codec matrix and dissection contract tests pass with only import changes.
- [x] `[Unreleased]` and the migration note list moved paths and error types.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Built-in modules renamed to `builtin/{assembly, bindings, filter_fields}.rs`.
- Large-protocol shape: `<proto>.rs` holds docs, the protocol `Error`/limits and
  re-exports; `model`/`codec`/`reflection` submodules may have children
  (`dns/codec/{decode, encode, name}`, `tls/codec/{parse, hello}`,
  `tls/model/{fingerprint, names}`, `http/codec/body`). TCP (`tcp/options.rs`)
  was also brought into the shape. DHCPv4/v6 share `dhcp/codec.rs` steps
  through a private `Message` trait instead of the macro.
- TLS also gains `tls::Error` (its wire APIs returned `codec::Error`), with
  unchanged Display text. Since the whole TLS tree moved, its submodules became
  private with flat re-exports now (ticket 13's TLS item); `dns::name` stays a
  public module for ticket 13.
- `Dns` wire errors: encoding failures are `dns::Error::Encode(codec::Error)`.
  `DecodeError` and `name::Error` are not merged (ticket 10).
- Test assertions changed only where the wire API error type changed
  (`dns_construction_contracts`, `protocol_end_to_end_contracts`); codec matrix
  and dissection tests have import changes only.
