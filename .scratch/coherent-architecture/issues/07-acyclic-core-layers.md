# 07: Acyclic core layers

**What to build:** Order core as model (`field`, `layer`, `layout`, `packet`, `frame`, `codec`, `registry`) → protocols (built-ins, `packet::semantics`, matchers) → engines (`decode`, `build`, `transform`, `filter`, `expression`) → `analysis`/`fuzz`, and remove every dependency that points across layers the wrong way.
- `packet::semantics` and the root `matcher` move under the protocol layer, which breaks the `packet`⇄`protocol` and `registry`→`matcher`→`packet`→`protocol`→`registry` cycles.
- Raw, Padding and Malformed become model layers in full: their codecs move out of `protocol/raw.rs`.
- Whether a link protocol allows trailing padding becomes a property recorded when the protocol is registered. It replaces the fixed `BuiltinProtocol` list in `decode/traversal.rs`, and the `build/validation.rs` Raw/Padding/Malformed special cases use model identity.
- The upward imports inside `protocol` go away: `transport/udp.rs` → `application::dns` heuristics, and `tunnel/geneve.rs` → `vxlan`.

Cycles inside the model layer are acceptable. Phase 1.

**Blocked by:** 04, 05

**Status:** resolved

- [x] No module imports from a higher layer. Add a short layer map to core's crate docs.
- [x] A custom protocol registered with the padding property behaves like the built-in link protocols. Add a contract test in `runtime_registry_contracts.rs`.
- [x] Decode and build matrix tests pass unchanged.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Per decisions.md, the root `matcher` (`ResponseMatcher`, `Match`) stays in the model layer beside the registry; the built-in matcher impls stay in `protocol/matcher`. Moving `packet::semantics` to `protocol::semantics` breaks both cycles.
- Raw, Padding and Malformed models, codecs and `parse_hex` now live in `layer/opaque.rs`; `protocol::raw` is removed and `parse_hex` is `layer::parse_hex`.
- The padding property is `registry::Builder::allow_trailing_padding(protocol)`, called beside the codec registration (a separate builder call, like `register_matcher`, so `register_codec`'s signature is unchanged); `build` rejects an unregistered protocol. `Registry::allows_trailing_padding` reads it.
- Build link-padding validation now uses the same property as decode, so VLAN/QinQ count as link protocols there too. A strict build of a VLAN-rooted packet with link padding now succeeds (it used to fail although decode produced it); recorded under Fixed.
- `build/validation.rs` keeps its protocol-specific boundary lists (IPv4/IPv6/UDP/ARP/PPPoE, Ethernet ether_type length); engines may depend on protocols. Only the Raw/Padding/Malformed cases moved to model identity.
- `#[cfg(test)]` code in `protocol/transport/udp.rs` (build + expression) and the TLS parse tests (`fuzz::rng`) still reach higher layers; they are unit tests, not module dependencies.
