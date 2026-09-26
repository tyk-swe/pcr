# 15: Move neighbor resolution to packetcraftr::neighbor

**What to build:** Per ADR 0001, neighbor resolution is active discovery composed from transmission and capture, so the whole `neighbor` module moves to `packetcraftr::neighbor`: resolver, cache, wire, options, evidence, error. `ActiveResolver` and the `SystemResolver` alias go away. The client resolves neighbors itself over its transmit and capture providers, so the CLI no longer composes a second I/O stack for resolution (`system/client.rs`). Any route materialization step left in netio that invokes resolution moves too. Phase 2. See `CONTEXT.md` **Neighbor resolution**.

**Blocked by:** 14

**Status:** resolved

- [x] netio has no `neighbor` module and no ARP/NDP code.
- [x] Neighbor resolution runs only after admission. Add a test: a packet rejected by policy causes no ARP/NDP transmission.
- [x] The resolver tests move with the code. The native-isolated neighbor tests pass on the Linux launcher.
- [x] `[Unreleased]` and the migration note list the moved paths.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Native-isolated coverage (decision C2): `native_isolated.rs` has no neighbor scenarios and its names are pinned to `NATIVE_SCENARIOS`, so none were added. It still compiles under the gate; the CI launcher is authoritative (user namespaces are unavailable here).
- Transitional composition (decision C3): `Client<R, I>` with `I: transmit::Sender + capture::Provider` on every path that materializes, including `send`. The client owns `neighbor::Options` and the cache (`Client::with_neighbor_options`). A crate-private `neighbor::Resolver` seam remains for materialization unit tests, which makes `route::materialize` crate-private. Ticket 25 does the final provider split.
- Public tests that scripted resolution now answer ARP requests through the capture session armed for them (`tests/common` `RecordingTransmit`). The deadline test checks that discovery waits are clipped to the exchange deadline. The new admission test lives in `staged_preparation_contracts.rs`.
- Also moved: `link::MAX_VLAN_TAGS` is now `packetcraftr::route::MAX_VLAN_TAGS`, because netio no longer uses it. The ARP/NDP wire code is unchanged; ticket 16 rewrites it.
- `Options::validate` now keeps the capture-limit refusal as the `source` of `InvalidOptions` (new `source: Option<netio::Error>` field) instead of flattening it into the message, as the exploration notes asked.
