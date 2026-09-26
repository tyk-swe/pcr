# 07: Acyclic core layers

**What to build:** Order core as model (`field`, `layer`, `layout`, `packet`, `frame`, `codec`, `registry`) → protocols (built-ins, `packet::semantics`, matchers) → engines (`decode`, `build`, `transform`, `filter`, `expression`) → `analysis`/`fuzz`, and remove every dependency that points across layers the wrong way.
- `packet::semantics` and the root `matcher` move under the protocol layer, which breaks the `packet`⇄`protocol` and `registry`→`matcher`→`packet`→`protocol`→`registry` cycles.
- Raw, Padding and Malformed become model layers in full: their codecs move out of `protocol/raw.rs`.
- Whether a link protocol allows trailing padding becomes a property recorded when the protocol is registered. It replaces the fixed `BuiltinProtocol` list in `decode/traversal.rs`, and the `build/validation.rs` Raw/Padding/Malformed special cases use model identity.
- The upward imports inside `protocol` go away: `transport/udp.rs` → `application::dns` heuristics, and `tunnel/geneve.rs` → `vxlan`.

Cycles inside the model layer are acceptable. Phase 1.

**Blocked by:** 04, 05

**Status:** ready-for-agent

- [ ] No module imports from a higher layer. Add a short layer map to core's crate docs.
- [ ] A custom protocol registered with the padding property behaves like the built-in link protocols. Add a contract test in `runtime_registry_contracts.rs`.
- [ ] Decode and build matrix tests pass unchanged.
- [ ] fmt, clippy and the workspace tests pass.
