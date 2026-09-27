# 05: Promote capture formats to core::capture_file

**What to build:** `analysis::pcap` (classic, pcapng, reader, writer, merge, map, rewrite, compression, wire, error, model) becomes the top-level module `capture_file`. It also owns link types and a single link-type ↔ root-protocol mapping, which replaces the four copies: the `frame.rs` constants, `protocol/capture` `BUILTIN_CAPTURE_ROOTS`, the hand-written reverse map in `fuzz/decode.rs`, and `transform/rewrite.rs`. Live replay and the CLI import from the new path. Phase 1. See `CONTEXT.md` **Capture file**.

**Blocked by:** 01

**Status:** resolved

- [x] `analysis` no longer contains capture-format code, and `capture_file` imports nothing from `analysis`.
- [x] Link-type knowledge exists once. A matrix test covers every mapped link type in both directions.
- [x] Capture merge, rewrite and reader contract tests pass with only import changes.
- [x] `[Unreleased]` and the migration note list the path change.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- `frame::LinkType` stays the model type in `frame` (per orchestrator decision): `Frame` and the registry use it and `examples/` must not change. `capture_file/link_type.rs` defines its constants and the one mapping (`LinkType::BUILTIN_ROOTS`, `root_protocol`, `for_root_protocol`, `is_raw_ip`), so the path stays `frame::LinkType`.
- `protocol::capture::{CaptureRoot, BUILTIN_CAPTURE_ROOTS}` are removed. `fuzz::packet_link_type` keeps its signature and uses the mapping. `transform::fragment`, `packetcraftr::replay` link-mode selection and the fuzz overhead estimate also use `is_raw_ip`.
- Left for ticket 37: the CLI `fragment.rs` root → link-type choice. The CLI `--link-type` name parser also stays, because its names are frozen CLI vocabulary.
- The mapping depends on `protocol::BuiltinProtocol`, so `capture_file` sits at the protocols layer or above (for ticket 07's layer map).
