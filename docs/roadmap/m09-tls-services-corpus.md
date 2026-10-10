# M9: TLS services and identification corpus

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M8][m8] | Qualified service inventory |

[M8][m8] identifies services that answer in cleartext, from a starter corpus of
three protocols. Many services sit behind TLS, and PacketcraftR has no active
TLS transport: its TLS support parses captured handshakes and computes client
fingerprints, which says nothing about the application inside a session it did
not open. A starter corpus also cannot support a coverage or confidence claim
until it has been measured on services its rules were not written against.

This milestone adds TLS-wrapped interrogation, grows the corpus under review,
and evaluates what the corpus can honestly claim.

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

## Decisions to settle

1. The TLS library (recommended: choose under the [`deny.toml`][deny] license
   list and duplicate-version rule, preferring an implementation that needs no
   system library, and record the review).
2. Which crate owns the TLS transport (recommended: netio owns the bounded
   stream and the workflow crate owns policy and budgets, keeping core free of
   native I/O).
3. How certificates are treated (recommended: make no trust decision; record
   the presented chain as an observation).
4. Which name, if any, is sent as SNI (recommended: the declared hostname when
   the target was declared by name, none for a numeric target, and never a
   name obtained by resolution the operator did not authorize).
5. How the held-out set is chosen (recommended: by service instance, fixed
   before rule writing begins, and recorded with the corpus version).
6. The source of CPE data (recommended: settle under the
   [M1 data policy][m1-data]; emit a CPE only where the match document carries
   one with provenance).

## Exit criteria

- [ ] Encrypted services have explicit fixture outcomes.
- [ ] The TLS dependency has a recorded dependency and license review.
- [ ] Passive TLS and JA3/JA4 observations are never presented as service
      identification.
- [ ] Claimed coverage and confidence are evaluated against held-out fixtures,
      not only the examples used to write rules.
- [ ] Hostname, device, and CPE metadata appear only when supported by an
      observation and the matching data.
- [ ] Every corpus addition has a provenance record and a read-only review.
- [ ] Applicable portable and native behavior passes on Linux, macOS, and
      Windows, and contract changes follow the
      [compatibility policy][compatibility].

[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m8]: m08-service-identification.md
[compatibility]: ../consumer-compatibility.md
[deny]: ../../deny.toml
