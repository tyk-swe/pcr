# M9: TLS services and identification corpus

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M8][m8] | Qualified service inventory |

M8 introduced cleartext identification for HTTP, SSH, and DNS. M9 adds bounded
TLS wrapping and reviewed SMTP/FTP greeting rules, while keeping captured TLS
handshakes and client fingerprints separate from active service evidence. Its
fixed held-out fixtures measure coverage and uncertainty beyond the rule-authoring
instances; they do not establish production prevalence or authenticated identity.

## Outcome

- Identification probes can run inside a TLS session opened over a bounded,
  reviewed transport.
- The corpus expands beyond HTTP, SSH, and DNS, one reviewed addition at a
  time.
- Coverage and confidence claims are measured against held-out fixtures.
- Hostname, device, and CPE metadata appear only where observations and
  matching data support them.

## Invariants

- Passive TLS decoding and JA3/JA4 observations are not service identification
  and are never published as such.
- A presented certificate is an observation. It does not authenticate the
  service or the host.
- New runtime dependencies pass the normal dependency and license review before
  they are added.
- Coverage is stated against declared fixtures, never against the size of
  another tool's database.

## Scope

### M9.1 Bounded TLS transport

- An active TLS client transport with explicit byte, time, and handshake
  limits, cancellable like other native resources.
- The transport's dependencies are reviewed for license, maintenance, and
  duplicate versions, and recorded in the third-party notices.

### M9.2 TLS-wrapped interrogation

- [M8][m8] probes run inside a TLS session, starting with HTTPS.
- The session is covered by the same reauthorization, read-only rule, and
  budgets as cleartext identification.
- A failed or refused handshake is an outcome with its evidence, not an
  unidentified cleartext service.

### M9.3 Corpus expansion

- Additional protocols and products are added to the corpus, each with a
  provenance record, a read-only review, and fixtures.
- Every addition states which fixtures it was written against.

### M9.4 Held-out evaluation

- A set of fixtures is held out before rules are written and is not used to
  write or tune them.
- Claimed coverage and confidence are evaluated on the held-out set and
  published with the corpus version they describe.
- The share of held-out services reported as unknown or ambiguous is part of
  the result.

### M9.5 Hostname, device, and CPE metadata

- Hostname, device-type, and CPE metadata are added to identification records
  only when an observation and the matching data support them.
- Each value names its source. An unsupported field is absent, not guessed.

## Settled decisions and implementation

- `packetcraftr-netio::tls` owns the bounded active transport. rustls 0.23.45
  with ring 0.17.14 provides TLS 1.2/1.3 without a system TLS library. The
  [dependency review](../../THIRD_PARTY_NOTICES.md#active-tls-transport-dependency-review)
  records exact licenses, duplicate exceptions, and maintenance rationale.
- `identify::Request::tls` explicitly wraps selected TCP probes. The workflow
  owns authorization, aggregate encrypted budgets, retained certificates, and
  all application budget scopes. Core remains free of native I/O.
- Numeric endpoints send no SNI. `--server-name` declares a DNS name without
  lookup; no certificate trust or hostname decision is made. Presented DER
  chains and negotiated parameters remain unauthenticated observations.
- Corpus 1.1.0 adds original SMTP/FTP greeting probes and reviewed match rules.
  New training fixtures and their source/read-only reviews are recorded in
  the [manifest](../../crates/packetcraftr/data/service-probes.provenance.yaml).
- The [21-instance held-out manifest](evidence/m09/held-out.v1.json) was fixed
  in commit `97267ae4` before rule authorship. Coverage, unknown/ambiguous
  outcomes, ordinal confidence, and misleading claims are measured separately.
- Observed SMTP hostname claims carry field/index sources. Reviewed rule-backed
  device and CPE values carry source references and existing corpus/rule
  provenance. The bundled corpus emits static product CPEs with wildcard
  versions, and no device types. NVD factual identifier review follows the
  [scanner data policy](../scanner-data-policy.md).
- Output/v13 freezes these additions; v12 remains published and immutable.
  [User guidance](../service-identification.md) explains budgets and evidence,
  and the [acceptance record](evidence/m09/README.md) owns runtime results.

## Exit criteria

- [ ] Encrypted services have explicit fixture outcomes.
- [x] The TLS dependency has a recorded dependency and license review.
- [x] Passive TLS and JA3/JA4 observations are never presented as service
      identification.
- [ ] Claimed coverage and confidence are evaluated against held-out fixtures,
      not only the examples used to write rules.
- [x] Hostname, device, and CPE metadata appear only when supported by an
      observation and the matching data.
- [x] Every corpus addition has a provenance record and a read-only review.
- [ ] Applicable portable and native behavior passes on Linux, macOS, and
      Windows, and contract changes follow the
      [compatibility policy][compatibility].

[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m8]: m08-service-identification.md
[compatibility]: ../consumer-compatibility.md
[deny]: ../../deny.toml
