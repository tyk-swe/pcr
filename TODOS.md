# Deferred work

Items ruled out of a shipped change on purpose, with the change that deferred
them. Each is a candidate, not a commitment.

## TLS (deferred from the `tls` session command)

- `stats --tls`: a TLS section in the statistics tables, alongside `protocols`
  and `conversations`.
- Expert codes `tls.malformed`, `tls.handshake_gap`, `tls.deprecated_version`,
  `tls.compression_negotiated`, and `tls.fatal_alert`.
- Content-sniffed dispatch, so a TLS record on an unbound TCP port dissects as
  `tls` per frame without `--tls-port`.
- Certificate summary: subject, issuer, validity, and SANs from the TLS 1.2
  certificate chain.
- `tls diff`: compare two captures' sessions by fingerprint and parameters.
- An active TLS prober that sends a ClientHello and reports what a server
  selects, reusing the same parser.
- JA4S and the rest of the JA4+ family.
- QUIC and DTLS handshakes, including the UDP/443 frames `tls` counts today.
- A `StreamCollector` trait shared by `follow`, `expert`, and `tls`, once a
  fourth collector says what the trait should be.
- `--columns` field selection for text output, in the shape of `tshark -T
  fields -e`.
- Partial hello reporting: keep what parsed before a failing extension. Today
  one bad optional extension makes the whole hello `malformed` and hides the
  fingerprint that did parse, and a first message shaped like a ServerHello
  poisons the role election for the stream.
- Hot-path allocation work, with a benchmark first so the win is measured:
  borrow record bodies in the per-frame codec instead of one
  `Bytes::copy_from_slice` per record, and expose TCP flags on `FrameRecord` so
  collectors stop re-walking the layer stack for every frame.
- A typed captured-direction enum in `analysis::tls::session`, in place of the
  `usize` index the buffers are keyed by.
- A published full-ClientHello JA3 MD5 and JA4 hash vector taken from a real
  capture, so the fingerprints are checked against something other than our own
  builder.

## 0.6 output-contract break

The v1 output contract is kept byte-stable through 0.5. These are the changes
that wait for a deliberate, single contract bump; none of them is a cleanup to
slip into an unrelated change.

- Classification codes `cli.*` and `Kind::Cli` (`packetcraftr-core::error`)
  name a consumer three layers up. They mean "caller or request error";
  rename to `request.*` / `Kind::Request` and keep exit code 2.
- Durations serialize as `std::time::Duration`'s `{secs, nanos}` object
  (`$defs/duration` in the schema). The rest of the surface is
  milliseconds-as-number (`--timeout-ms`, `handshake_rtt_ms`); switch to `*_ms`.
- Schema descriptions name CLI flags (`--max-tls-sessions`, at the two
  `tls` limit fields). Describe the field, not the flag.
- `exchange --max-unsolicited` is the same concept as `--max-undecoded` on
  `scan`, `dns`, and `traceroute`. Rename.
- `tls --max-tls-buffer-bytes` / `--max-tls-sessions` carry the command name;
  the offline readers do not (`read --max-frames`, not `--max-read-frames`).
  Drop the prefix, and rename `capture --max-captured-bytes` in the same pass
  so no flag carries its command's name.
- Help strings are outside the byte-stable guarantee: `capture --max-packets`
  was reworded in 0.5 without a bump. Only serialized documents, classification
  codes, exit codes, flag names, and defaults are held stable.

## Review follow-ups (2026-08-26 recovery pass)

Design points raised in review and left as they are, each needing a decision
rather than a mechanical edit.

- `authorization::Operation` derives `Default` and every call site ends in
  `..Operation::default()`, so a field a workflow forgets to set takes the
  permissive value. Each authorizer reads only its subset of the fields.
  Options: document per-field ownership and assert on unexpected
  combinations, or split the seam into per-shape request types so an unread
  field fails to compile.
- `fuzz`, `replay`, and `target` re-export the authorization types verbatim,
  so one seam has four import paths. Drop the re-exports or deprecate them.
- The narrowed format enums in `commands/format.rs` have no conversion between
  them; four call sites hand-write a variant-for-variant match to re-narrow.
  Teach `narrowed_format!` to generate the mapping.
- The ephemeral source-port base 49_152 is declared twice and the rotation
  over that range is written three ways (`scan/probe.rs`, `dns/engine.rs`, the
  CLI's `dns/conversion.rs`). One constant, one helper.
- The deny sweep covers `[]` and arithmetic but not the panicking range APIs
  (`Vec::drain`, `slice::chunks`, `Bytes::slice`). Two sit behind a
  `debug_assert!` or validation in another function
  (`analysis/reassembly/tcp/state.rs` `drain(..old_start)`, `scan/plan.rs`
  `chunks(batch_size)`). Decide whether to guard them or lint them.
- `packetcraftr-cli/tests/ndjson_conformance.rs` reproduces the message
  template of `CliError::with_cleanup` as a literal instead of calling it;
  the composition is no longer covered by that test.

## Architecture

- The four-crate topology (`core` → `netio` → `packetcraftr` → `cli`) from the
  2026-08 consolidation is settled. Further moves need a reason, not a tidy-up.
- `StreamCollector` trait (see TLS above): still waiting for the fourth
  collector.

## Distribution

- `cargo install packetcraftr-cli`: the workspace crates are `publish = false`,
  so installation is from a release archive or from source. Publishing is an
  owner decision about the AGPL crates, not a technical blocker.
