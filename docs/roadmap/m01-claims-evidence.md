# M1: Claims and evidence model

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Complete | None | [M2][m2], [M4][m4], [M6][m6], and the vocabulary every later milestone publishes |

PacketcraftR's scan output already records per-probe classifications, reasons,
timestamps, RTT, and captured responses. It uses one vocabulary for all of it:
the same `Classification` describes what one attempt observed and what the
endpoint aggregate reports. Host discovery, state inference, and identification
each add a different kind of claim, and each depends on data (port names,
payloads, probes, fingerprints, vendor prefixes) that the project has no policy
for acquiring.

This milestone defines what can be claimed, and what data may be shipped,
before any feature depends on either. It adds no scanner capability.

## Outcome

- Host observations, scan-dependent port inference, per-attempt probe or socket
  outcomes, and operational failures are four separately defined vocabularies.
- The current timeout, unreachable, and unknown evidence is retained rather
  than renamed to match Nmap's port vocabulary.
- A reviewed policy states where port, service, OS, and vendor data may come
  from, how it is versioned, who maintains it, and how coverage is described.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| Port vocabulary | One [`Classification`][scan-report] (`open`, `closed`, `filtered`, `unreachable`, `unknown`, `timeout`) on each probe and on the endpoint aggregate, which keeps the highest-ranked value | `open`, `closed`, `filtered`, `unfiltered`, `open\|filtered`, and idle-specific `closed\|filtered`, each scan-dependent ([state meanings][nmap-states]) |
| Host vocabulary | Resolved addresses and endpoint/probe evidence; no host record | Host state and reason ([host discovery][nmap-discovery]) |
| Reasons and evidence | Per-probe reasons, timestamps, RTT, captured responses, `probe_sent` records, and partial-failure evidence under [output v6][scan-output] | State reasons and packet tracing ([output][nmap-output]) |
| Scanner data | Bounded [UDP profile documents][udp-document] supplied by the operator; no bundled catalog and no data lifecycle | Port, probe/match, OS, and vendor databases under the [NPSL][nmap-license] |

## Scope

### M1.1 Evidence vocabulary

Define four vocabularies and the rules that keep them apart:

- **Attempt outcome.** What one probe or socket operation observed: a reply, an
  ICMP error, silence within its window, a late or unattributed frame. Today's
  per-probe classification, reason, and timestamps are this layer.
- **Port inference.** A scan-dependent conclusion drawn from one endpoint's
  attempts, with the rule that produced it. The same attempts can support
  different inferences under different scan methods. Conflicting attempts stay
  visible beside the inference.
- **Host observation.** Evidence that a host answered, by which probe, and
  whether the evidence is direct, a cached next hop, or a proxy reply.
- **Operational failure.** A missing backend, a refused permission, a socket
  deadline, an exhausted budget, or a cancellation. These are never expressed
  as a network observation.

The definitions state which vocabulary each existing output field belongs to,
so later milestones extend a layer instead of overloading one.

### M1.2 Scanner data policy

A written policy covering port, service, OS, and vendor data:

- **Provenance.** Every bundled data set records its source, retrieval date,
  and the transformation applied.
- **License review.** Each source is reviewed for redistribution under
  PacketcraftR's AGPL-3.0-only license before it is imported. Nmap code and
  data are not copied or bundled on the assumption that the
  [NPSL][nmap-license] is compatible.
- **Versioning.** Data sets carry their own version, separate from the binary
  and from the output contract, so a result can name the data that produced it.
- **Maintenance ownership.** Each data set has a named owner and a refresh
  procedure.
- **Coverage.** Claims about coverage are stated against declared fixtures, not
  against the size of another tool's database.

## Change map

| Change | Start here |
| --- | --- |
| Attempt and aggregate vocabulary | [`scan/report.rs`][scan-report], [`scan/evidence.rs`][scan-evidence] |
| Published scan records | [`output/scan.rs`][scan-output], [`output/contract.rs`][output-contract], `schemas/` |
| Contract rules | [Consumer compatibility policy][compatibility] |
| Bounded document precedent for data | [`document/udp_profiles.rs`][udp-document] |
| Policy text | A new document under `docs/`, linked from [Contributing][contributing] |

## Decisions

Settled at M1 with the recommended positions:

1. **Inferred states publish in a new output contract family, not in v6.**
   Port inference is scan-dependent: the same attempts can support different
   conclusions under different methods, and assigning inference meanings to
   the v6 classification enum would change what existing values promise. The
   [compatibility policy][compatibility] requires a new family for new enum
   meanings, so [M6][m6] introduces the inference family with the first
   inference it publishes. The v6 `classification` values keep their current
   attempt-observation semantics unchanged; the endpoint aggregate remains the
   highest-ranked attempt outcome, not a method-specific inference.
2. **M1 lands the written model only.** No Rust types ship without a
   producer. Each type lands beside its first producer in [M5][m5] and
   [M6][m6], so no unused public type exists. The model lives in
   [scanner evidence][evidence-doc].
3. **Data sources are decided per kind during license review.** The
   [scanner data policy][data-policy] records which sources are acceptable,
   which are candidates pending terms review, and which are rejected, with
   the reason for each rejection.
4. **Packaging is decided per data set with the first import in
   [M6][m6-catalog].** The policy permits both binary-bundled and separate
   release assets; each form requires the per-source review to pass first.

## Exit criteria

- [x] The four vocabularies are documented, and every field of the current
      scan records is assigned to one of them — [scanner
      evidence](../scanner-evidence.md).
- [x] The documented model retains the current timeout, unreachable, and
      unknown evidence as attempt outcomes — [attempt
      observations](../scanner-evidence.md#attempt-observations).
- [x] The data policy covers provenance, license review, versioning,
      maintenance ownership, and coverage for port, service, OS, and vendor
      data — [scanner data policy](../scanner-data-policy.md) with the
      [provenance template](../scanner-data-provenance-template.md).
- [x] Data sources are reviewed under that policy before any dependent feature
      is claimed complete — the [source review](../scanner-data-policy.md#source-review)
      gate is recorded; enforcement is procedural at each import, and no
      dependent feature is claimed complete yet.
- [x] Decisions 1 and 2 are recorded in this file with their rationale —
      [decisions](#decisions).

[data-policy]: ../scanner-data-policy.md
[evidence-doc]: ../scanner-evidence.md
[m2]: m02-ground-truth-benchmarks.md
[m4]: m04-target-planning.md
[m5]: m05-host-discovery.md
[m6]: m06-port-planning-inference.md
[m6-catalog]: m06-port-planning-inference.md#m61-port-catalog-and-named-selections
[contributing]: ../../CONTRIBUTING.md
[compatibility]: ../consumer-compatibility.md
[scan-report]: ../../crates/packetcraftr/src/scan/report.rs
[scan-evidence]: ../../crates/packetcraftr/src/scan/evidence.rs
[scan-output]: ../../crates/packetcraftr-cli/src/output/scan.rs
[output-contract]: ../../crates/packetcraftr-cli/src/output/contract.rs
[udp-document]: ../../crates/packetcraftr-core/src/document/udp_profiles.rs
[nmap-states]: https://nmap.org/book/man-port-scanning-basics.html
[nmap-discovery]: https://nmap.org/book/man-host-discovery.html
[nmap-output]: https://nmap.org/book/man-output.html
[nmap-license]: https://nmap.org/npsl/
