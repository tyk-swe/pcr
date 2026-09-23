# 07: Staged preparation module for send, send_set and exchange

**What to build:** The client's preparation seam becomes one module with a small interface. It takes an expansion of packets, the send options, the deadline and the operation's packet count for the count-only budget, and enforces the stage order in one of two modes. **All-before-discovery** (exchange): every packet passes planning, the preliminary build, MTU, packet and wire authorization, and the cumulative wire budget before any materialization, and prepared packets are kept. **Streaming** (`send_set`, and single send as streaming with one packet): each packet passes its preliminary checks and the cumulative budget, then is materialized, finally authorized and transmitted before the next is planned. Frames are emitted as they are confirmed, and repeat passes re-expand. In both modes the module owns the final endpoint and bytes check immediately before transmission, the transmit call, `SentPacket` construction, and the cumulative-bytes overflow → `ByteLimit` mapping, which now exists once. The ports stay `route::Provider`, `neighbor::Resolver` and `transmit::Sender`. See the spec's "Staged preparation" section.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] Single send, `send_set` and exchange no longer hand-sequence the chain. The three `ByteLimit` overflow blocks become one.
- [ ] Leave the module room for the scan pipeline's keep-or-rebuild use (ticket 08), without implementing it early.
- [ ] Tests go through the client with the test-support netio fakes (fixed routes, a recording neighbor resolver, a recording transmitter). They assert: in all-before-discovery mode, a packet rejected by policy late in the expansion triggers no neighbor call; in streaming mode, each packet is authorized before its own discovery and frames are emitted as they are confirmed; and cumulative-byte overflow surfaces as `ByteLimit`.
- [ ] The `send_set` and exchange-failure contract tests pass unchanged.
- [ ] fmt, clippy and the workspace tests pass.
