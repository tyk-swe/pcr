# 15: Move neighbor resolution to packetcraftr::neighbor

**What to build:** Per ADR 0001, neighbor resolution is active discovery composed from transmission and capture, so the whole `neighbor` module moves to `packetcraftr::neighbor`: resolver, cache, wire, options, evidence, error. `ActiveResolver` and the `SystemResolver` alias go away. The client resolves neighbors itself over its transmit and capture providers, so the CLI no longer composes a second I/O stack for resolution (`system/client.rs`). Any route materialization step left in netio that invokes resolution moves too. Phase 2. See `CONTEXT.md` **Neighbor resolution**.

**Blocked by:** 14

**Status:** ready-for-agent

- [ ] netio has no `neighbor` module and no ARP/NDP code.
- [ ] Neighbor resolution runs only after admission. Add a test: a packet rejected by policy causes no ARP/NDP transmission.
- [ ] The resolver tests move with the code. The native-isolated neighbor tests pass on the Linux launcher.
- [ ] `[Unreleased]` and the migration note list the moved paths.
- [ ] fmt, clippy and the workspace tests pass.
