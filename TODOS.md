# Deferred work

Items left out of a shipped change on purpose. Candidates, not commitments.

## TLS (deferred from the `tls` command)

- `stats --tls` section alongside `protocols` and `conversations`.
- Expert codes: `tls.malformed`, `tls.handshake_gap`,
  `tls.deprecated_version`, `tls.compression_negotiated`, `tls.fatal_alert`.
- Content-sniffed dispatch, so TLS on an unbound TCP port dissects without
  `--tls-port`.
- Certificate summary (subject, issuer, validity, SANs) from the TLS 1.2 chain.
- `tls diff`: compare two captures by fingerprint and parameters.
- Active prober: send a ClientHello, report the server's selection.
- JA4S and the rest of JA4+.
- QUIC and DTLS handshakes (`tls` only counts UDP/443 frames today).
- `StreamCollector` trait shared by `follow`, `expert`, and `tls`; wait for a
  fourth collector to show the shape.
- `--columns` field selection for text output (`tshark -T fields -e`).
- Partial hello reporting: keep what parsed before a failing extension. One bad
  optional extension currently marks the whole hello `malformed` and hides the
  fingerprint, and a first message shaped like a ServerHello poisons the
  stream's role election.
- Hot-path allocation, benchmark first: borrow record bodies in the per-frame
  codec instead of `Bytes::copy_from_slice` per record; expose TCP flags on
  `FrameRecord` so collectors stop re-walking the layer stack.
- Typed direction enum in `analysis::tls::session` instead of the `usize` key.
- A JA3 MD5 / JA4 vector from a real full ClientHello, so the fingerprints are
  checked against something other than our own builder.

## 0.6 output-contract break

The v1 contract is byte-stable through 0.5 (serialized documents,
classification codes, exit codes, flag names, defaults; help strings are not
covered). These wait for one deliberate bump:

- Rename `cli.*` / `Kind::Cli` (`packetcraftr-core::error`) to `request.*` /
  `Kind::Request`; keep exit code 2.
- Durations serialize as `{secs, nanos}` (`$defs/duration`); the rest of the
  surface is `*_ms`. Switch.
- Schema descriptions at the two `tls` limit fields name `--max-tls-sessions`.
  Describe the field, not the flag.
- `exchange --max-unsolicited` → `--max-undecoded`, matching `scan`, `dns`,
  `traceroute`.
- Drop command names from flags: `tls --max-tls-buffer-bytes`,
  `--max-tls-sessions`, `capture --max-captured-bytes`.

## Distribution

- Crates are `publish = false`; install is from a release archive or source.
  Publishing the AGPL crates is an owner decision.
