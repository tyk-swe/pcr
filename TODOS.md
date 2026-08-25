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

## Distribution

- `cargo install packetcraftr-cli`: the workspace crates are `publish = false`,
  so installation is from a release archive or from source. Publishing is an
  owner decision about the AGPL crates, not a technical blocker.
