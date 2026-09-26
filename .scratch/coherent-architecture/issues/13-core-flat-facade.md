# 13: Core flat facade

**What to build:** Apply the facade rule to core now that its paths are final.
- Submodules are private and items are re-exported flat. This includes `application::{dns,dhcp,http,ntp,tls}`: TLS's `codec`, `fingerprint`, `model`, `names` and `parse` become private, so the TLS model is `tls::Tls`.
- DNS name decoding keeps one public API (`decode_name` or `name::decompress`, not both), and the `read_u16` primitive becomes private.
- Nothing `#[doc(hidden)]` is used across crates. `layer::raw_layout`, the `reflect_*` family and the matcher helpers become real documented API or move to their user.
- The root `display_via_as_str!` macro either becomes documented public API or is replaced by derives in each crate.

Phase 1.

**Blocked by:** 09, 10, 11, 12

**Status:** resolved

- [x] No `#[doc(hidden)]` core item is referenced from another crate.
- [x] Each item is reachable by exactly one public path.
- [x] `scripts/check-external-consumer.py` passes.
- [x] `[Unreleased]` and the migration note list the path changes.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- `display_via_as_str!` is private to core; netio, packetcraftr, and the CLI
  implement `Display` by hand (the CLI edit is two impls in
  `output/contract.rs`).
- Renamed the correlation helpers while documenting them:
  `QuotedIcmpError` (not an error type) is `IcmpErrorKind`,
  `QuotedProbeTransport` is `QuotedTransport`, `quoted_icmp_error_kind` is
  `quoted_icmp_error`. `raw_layout` became `Raw::layout`.
- Beyond the ticket text: `packet::link` flattened into `packet`, and the
  `frame::GlobalInterfaceId = u32` alias removed. Nested public modules kept
  as sub-domains: the `analysis` analyses, `reassembly::{ip, tcp}`,
  `capture_file::compression` (own `Limits`), the protocol groups,
  `protocol::{builtin, headers, semantics}`, and the constant namespaces
  `network::ip_protocol` and `tls::extension`.
- Ticket 10's leftovers: `transform::Error` and `fuzz::Error` reasons are
  typed with byte-identical messages. The CLI's fragment root check uses the
  new `transform::Unsupported::PacketRoot` until ticket 37 moves it. The
  unreachable case-time fuzz message "layer is outside the packet" now reads
  like the resolve-time one ("layer index is outside packet length N").
  Edge path parse failures (`set_document_field`, `Template::axis`) still
  report `field::Error::UnknownField`: a key that is not a path names no
  field, and `InvalidPath` would change published messages.
- `examples/consumers/rust/composition.rs` imports `packet::MacAddress`.
- Verified with rustdoc JSON (nightly): 601 public items, no item at two
  paths, no hidden item.
