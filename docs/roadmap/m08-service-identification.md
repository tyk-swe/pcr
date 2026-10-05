# M8: Service and version identification

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M7][m7] | [M9][m9] |

A scan says a port answered. It does not say what is listening. PacketcraftR's
closest existing feature is the UDP profile, which sends a configured request
and reports whether configured checks matched; `confirmed` there means the
checks matched, not that a product was identified. The workflow crate exposes
no identification engine, corpus, or result record.

This milestone adds read-only identification of the application behind an
endpoint, as an explicit operation with its own budgets, and reports what was
observed separately from what was inferred.

## Outcome

- An explicit identification operation interrogates endpoints a scan reported,
  under per-host, per-connection, and per-probe limits.
- Banner and protocol-aware probes identify HTTP, SSH, and DNS services on any
  port.
- Probes and matches live in versioned, bounded documents with provenance.
- Results separate observed claims, matched candidates, confidence, and the
  evidence behind each.
- Intensity is configurable, and sensitive-service exclusions keep probes away
  from endpoints that should not receive them.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| Identification | None in the [workflow surface][workflow-surface]; [UDP profile][udp-profiles] status (`not_observed`, `unchecked`, `confirmed`, `rejected`) reports configured checks | Active TCP/UDP response matching, including nonstandard ports ([version detection][nmap-version]) |
| Streams | The [TCP provider][tcp-provider] supplies ordinary streams, used by connect scanning and DNS over TCP | Probes over TCP and UDP ([version detection][nmap-version]) |
| Protocol parsing | Core codecs for DNS, HTTP, and TLS among others ([application protocols][core-application]); no SSH banner parser | Probe/match database ([version detection][nmap-version]) |
| Result record | [Scan records][scan-output] carry endpoint, probe, and configured-profile evidence; no candidate or confidence model | Product, version, and extra information ([version detection][nmap-version]) |
| Controls | Explicit bounded UDP profile configuration | Intensity levels and excluded ports ([version detection][nmap-version]) |

## Invariants

- Identification is read-only. No probe authenticates, changes state, or
  follows a redirect.
- Identification is an explicit operation. A scan does not start it on its own.
- Final numeric endpoints are reauthorized before each connection or datagram.
- A banner is an untrusted claim. It is never published as authenticated
  identity.
- An identified version is not an assertion that the service is vulnerable.

## Scope

### M8.1 Identification workflow and budgets

- An identification operation over selected endpoints, with explicit byte,
  time, and attempt limits per host, per connection, and per probe, inside the
  operation's budget.
- Hidden resolution, redirects, authentication attempts, and extra probing
  cannot bypass the declared policy and budget.
- Truncated and malformed replies are evidence with their own outcomes, not
  errors that discard what was read.

### M8.2 Banner and protocol-aware probes

- Banner collection for services that speak first, starting with SSH.
- Protocol-aware requests for HTTP and DNS, reusing core parsing.
- Both TCP and UDP endpoints are supported. HTTPS and other TLS-wrapped
  services belong to [M9][m9-tls].

### M8.3 Probe and match documents

- A versioned, bounded document format for probes and matches, parsed and
  matched in core with no native I/O.
- Each entry carries maintenance and provenance metadata under the
  [M1 data policy][m1-data].
- UDP profile building blocks are reused. A profile's `confirmed` status keeps
  its meaning and is not reinterpreted as product identity.

### M8.4 Identification records

Four separate things are published for each endpoint:

- **Observed claims**: the protocol spoken and the banner or fields received.
- **Candidates**: products and versions the corpus matched.
- **Confidence**: how strongly the evidence supports each candidate.
- **Provenance**: which probe, which response bytes, and which corpus version
  produced the match.

Unknown and ambiguous cases are results in their own right.

### M8.5 Intensity and sensitive-service exclusions

- Intensity controls that bound how many probes an endpoint receives.
- Sensitive-service exclusions that keep identification away from endpoints
  where an unsolicited probe is unsafe, applied before any probe is planned.

## Change map

| Change | Start here |
| --- | --- |
| Identification workflow | A new workflow module beside [`scan`][scan-limits], exported from [`lib.rs`][workflow-surface] |
| Bounded streams | netio [`tcp.rs`][tcp-provider] |
| Probe and match documents | core [`document/`][core-document], with [`udp_profiles.rs`][udp-document] as the precedent |
| Protocol parsing | core [`protocol/application/`][core-application] |
| UDP building blocks | [`scan/profile.rs`][udp-profiles] |
| Records and contract | [`output/scan.rs`][scan-output], [`output/contract.rs`][output-contract], `schemas/` |

## Decisions to settle

1. Whether identification is a stage of `scan` or a separate command
   (recommended: a stage that runs only when requested, over endpoints the scan
   reported, so one authorization and budget cover both).
2. The match language (recommended: start with anchored literals and bounded
   field extraction over parsed protocol structures; add a pattern language
   only with a linear-time engine and a dependency review).
3. How confidence is expressed (recommended: ordinal levels defined by which
   evidence supports the candidate, evaluated in [M9][m9-evaluation], not a
   probability nobody has measured).
4. The default sensitive-service exclusions (recommended: a reviewed list
   shipped as data under the [M1 data policy][m1-data], overridable only
   explicitly).
5. What qualifies a probe as read-only (recommended: a per-probe review record
   stating that it does not authenticate, change state, or follow redirects).

## Exit criteria

- [ ] Known services on nonstandard ports, unknown services, ambiguous matches,
      misleading banners, truncation, and malformed replies each have an
      explicit fixture outcome.
- [ ] Unknown and ambiguous cases never become exact versions.
- [ ] Reauthorization covers the final numeric endpoint of every connection and
      datagram.
- [ ] Hidden resolution, redirects, authentication attempts, and extra probing
      cannot bypass the declared policy and budget.
- [ ] Identification runs only as an explicit operation.
- [ ] A given corpus version reproduces the same matching results for the same
      evidence.
- [ ] No output or document presents an identified version as a vulnerability
      finding.
- [ ] Applicable portable and native behavior passes on Linux, macOS, and
      Windows, and contract changes follow the
      [compatibility policy][compatibility].

[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m7]: m07-adaptive-scheduling.md
[m9]: m09-tls-services-corpus.md
[m9-tls]: m09-tls-services-corpus.md#m92-tls-wrapped-interrogation
[m9-evaluation]: m09-tls-services-corpus.md#m94-held-out-evaluation
[compatibility]: ../consumer-compatibility.md
[workflow-surface]: ../../crates/packetcraftr/src/lib.rs
[scan-limits]: ../../crates/packetcraftr/src/scan.rs
[udp-profiles]: ../../crates/packetcraftr/src/scan/profile.rs
[tcp-provider]: ../../crates/packetcraftr-netio/src/tcp.rs
[core-document]: ../../crates/packetcraftr-core/src/document.rs
[udp-document]: ../../crates/packetcraftr-core/src/document/udp_profiles.rs
[core-application]: ../../crates/packetcraftr-core/src/protocol/application.rs
[scan-output]: ../../crates/packetcraftr-cli/src/output/scan.rs
[output-contract]: ../../crates/packetcraftr-cli/src/output/contract.rs
[nmap-version]: https://nmap.org/book/man-version-detection.html
