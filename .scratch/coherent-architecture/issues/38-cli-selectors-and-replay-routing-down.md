# 38: Move selectors and replay routing out of the CLI

**What to build:**
- These move to core `analysis`/`filter`, beside what they select over: the TLS session/SNI wildcard selector (`tls/mod.rs`), the expert-finding selector (`expert/mod.rs`) and `FrameDecoder`/`FrameSelector` (`filtering.rs`).
- Typed stream selectors no longer turn back into filter text (`"tcp.stream == N"` in `dns_read`, `http` and `tls`).
- Replay interface routing (`SOURCE=IF` / `EXPR=>IF` parsing and conflict resolution in `replay/{mod,selection}.rs`) moves to `packetcraftr::replay` as part of its request.
- Capture ring and rotation (`capture/files.rs`) stays in the CLI.

Phase 4.

**Blocked by:** 31, 35

**Status:** resolved

- [x] The CLI has no domain selectors or routing logic.
- [x] Unit tests move with the code, and the CLI process tests pass unchanged.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Paths were stale: the selectors lived in `commands/tls.rs`, `commands/expert.rs`, `filtering.rs`, and `commands/replay.rs` + `replay/selection.rs`.
- Per decision C4, `filtering::compile`/`Capabilities` (the CLI-worded stream-capability refusal) and `matches_decoded` stay in the CLI; core `filter::{FrameDecoder, FrameSelector}` take a compiled filter and refuse stream-index filters with a neutral, CLI-unreachable `filter::Error::StreamIndexUnavailable`. `filter::Error::Decode` is transparent, so `policy.decode_resource_limit` is preserved; `filter::Error` loses `PartialEq`/`Eq`.
- Stream selection is typed: `analysis::Options::stream`, applied by `Session::new`. The `--help` text that says "applied as 'tcp.stream == N'" still describes the behavior and is unchanged.
- Replay routing had no tests to move (C5): added 7 packetcraftr routing unit tests and 2 `client.replay` routing tests; the CLI frame-selector tests moved to core `filter/frames.rs`.
- Messages (codes, exit codes, coordinates unchanged; CHANGELOG Changed): conflicting/unmapped replay frames publish the bare sentence (C8); refused `--sni` and `--map-interface`/`--map-filter` values keep their message and gain the library refusal as causes (C4). A byte-identity harness over 198 tls/follow/dns-read/http/expert/read/stats/rewrite/capture/replay runs differed only there.
- `output::replay::Report`'s `TryFrom` tuple takes any `Option<I: Into<InterfaceId>>`, so the CLI tests compile unchanged while the command passes the routing's `route::Interface` fallback.
