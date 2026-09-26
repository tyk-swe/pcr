# 05: Promote capture formats to core::capture_file

**What to build:** `analysis::pcap` (classic, pcapng, reader, writer, merge, map, rewrite, compression, wire, error, model) becomes the top-level module `capture_file`. It also owns link types and a single link-type ↔ root-protocol mapping, which replaces the four copies: the `frame.rs` constants, `protocol/capture` `BUILTIN_CAPTURE_ROOTS`, the hand-written reverse map in `fuzz/decode.rs`, and `transform/rewrite.rs`. Live replay and the CLI import from the new path. Phase 1. See `CONTEXT.md` **Capture file**.

**Blocked by:** 01

**Status:** ready-for-agent

- [ ] `analysis` no longer contains capture-format code, and `capture_file` imports nothing from `analysis`.
- [ ] Link-type knowledge exists once. A matrix test covers every mapped link type in both directions.
- [ ] Capture merge, rewrite and reader contract tests pass with only import changes.
- [ ] `[Unreleased]` and the migration note list the path change.
- [ ] fmt, clippy and the workspace tests pass.
