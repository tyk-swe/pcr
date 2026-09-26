# 11: Limits and budgets in core

**What to build:** Apply the vocabulary in `CONTEXT.md` (**Limit**, **Budget**).
- A configured ceiling is a `…Limits` type with `validate()`, called when the type is constructed or accepted. Only 8 of the 15+ have one today. Add it to the reassembly, capture-file, compression, scope and DHCP limits.
- A running allowance is a `…Budget`.
- DHCP's silent clamp of the caller's limits (`dhcp/mod.rs`) becomes a validation error.
- `pipeline/limits.rs` stops copying the reassembly limits into its own fields and holds them directly.
- `decode::Options` and `build::Options` share their common limit fields through one type.

No shared budget primitive.

Phase 1.

**Blocked by:** 10

**Status:** resolved

- [x] Every limits type validates. A limit above its ceiling fails with a classified error and is never lowered silently. Add a DHCP contract test.
- [x] Types are renamed to match Limit/Budget, and `[Unreleased]` and the migration note list them.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Engines validate only what they cannot honor: the TCP window ceiling and an
  idle expiry beyond the monotonic clock. Zero stays a valid "refuse this
  resource" setting for the reassemblers, scope interner, `ReaderLimits`,
  `VerifyLimits`, `RewriteLimits`, and the new `packet::Limits`; the offline
  pipeline keeps rejecting zero for every field as before. The last four have
  no invalid value, so they document what zero means instead of gaining a
  `validate()` that accepts everything.
- New validation errors reuse existing codes: `cli.capture_limit` (capture
  stream limits), `cli.analysis_limit` (reassembly and scope limits),
  `policy.dhcp_limit`, `policy.dns_limit`, `cli.capture_merge_sources`,
  `packet.capture_compression_limit`. No new code.
- Beyond the ticket: DNS `DecodeLimits` also tightened oversized limits
  silently; that is now a validation error too (behavior fix, own changelog
  entry). `capture_file::ReaderOptions` is renamed `ReaderLimits`, and
  `Limits::advance` became `capture_file::Budget`.
- `analysis::Limits.tcp.max_flows` is held directly, so it is no longer derived
  from `max_flows`; its default (and the CLI call site) keep twice `max_flows`.
- `expression::Options` and `filter::Options` are also pure ceilings named
  Options; they were left for a later rename (filter already validates).
