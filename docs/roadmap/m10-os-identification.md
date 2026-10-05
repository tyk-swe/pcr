# M10: OS identification

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M5][m5], [M7][m7] | Qualified OS inventory |

PacketcraftR can build and decode the packets a stack fingerprint needs, and it
has nothing that collects one. There is no probe set, no fingerprint
representation, no matching corpus, and no result that says which operating
system a host is likely to run. The fingerprints it does compute, JA3 and JA4,
describe a TLS client seen in a capture, not the stack of a remote host.

This milestone adds active stack-fingerprint collection for both IP families
and matching against a reviewed corpus, with results that say plainly when the
evidence is not good enough.

## Outcome

- A finite, explicit probe set collects a stack fingerprint over IPv4, and a
  separately defined one over IPv6.
- Fingerprints and the matching corpus are bounded documents, matched in core.
- Suitability is checked before matching, and results are ranked candidates
  with evaluated confidence, or explicitly unsupported or inconclusive.
- The corpus is reviewed, versioned, and evaluated against held-out fixtures.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| Collection | No OS-fingerprint workflow in the [workflow surface][workflow-surface] or [scan reports][scan-report] | Stack fingerprints from a defined probe sequence ([OS detection][nmap-os]) |
| Building blocks | Core [TCP][tcp-codec], [network-layer][core-network], and ICMP codecs; [matchers][core-matcher] for echo replies, quoted ICMP, and reverse flows | Not applicable |
| Matching | None | Fingerprint database with candidates and confidence ([OS detection][nmap-os]) |
| Suitability | None | Suitability checks before reporting a match ([OS detection][nmap-os]) |
| Other fingerprints | Passive JA3/JA3S/JA4 from captured TLS handshakes ([TLS analysis][tls-analysis]) | Not an OS-detection input |

## Invariants

- Service banners and passive TLS client fingerprints are not remote OS proof.
- Missing suitability conditions or an ambiguous match never produce an exact
  label.
- A reply that may have come from a NAT device or another intermediary is not
  attributed to the target's stack without evidence.
- Fingerprint probes are authorized, finite, and checked at the final wire like
  any other transmission.

## Scope

### M10.1 IPv4 fingerprint collection

An explicit, finite IPv4 probe set, with the probe and evidence requirements
written down: which probes are sent, what each response contributes, and what
is needed before a fingerprint is usable.

### M10.2 IPv6 fingerprint collection

An explicit, finite IPv6 probe set with its own probe and evidence
requirements. The IPv4 method is not assumed to transfer unchanged.

### M10.3 Fingerprint documents and matching

- A bounded fingerprint representation and a versioned corpus document format,
  parsed in core.
- Pure matching in core that returns ranked candidates, with no native I/O and
  no live policy.

### M10.4 Suitability and qualified results

- Suitability checks run before matching and name each missing condition.
- Results are ranked candidates with evaluated confidence.
- Missing evidence yields an explicit unsupported or inconclusive result, never
  a weaker-looking exact label.

### M10.5 Corpus and held-out evaluation

- A reviewed matching corpus, each entry with a provenance record under the
  [M1 data policy][m1-data].
- Known and held-out fixtures, with the held-out set fixed before entries are
  tuned.
- Confidence is evaluated on the held-out set and published with the corpus
  version.

## Change map

| Change | Start here |
| --- | --- |
| Collection workflow | A new workflow module beside [`scan`][scan-limits], exported from [`lib.rs`][workflow-surface] |
| Probe construction and correlation | [`scan/plan/packet.rs`][scan-packets], [`correlation.rs`][correlation] |
| Stack features | core [`protocol/transport/tcp.rs`][tcp-codec], [`protocol/network.rs`][core-network] |
| Response matching | core [`protocol/matcher.rs`][core-matcher] |
| Fingerprint and corpus documents | core [`document.rs`][core-document] |
| Packet resources | netio [`transmit.rs`][netio-transmit], [`capture.rs`][netio-capture] |
| Qualified inventory output | [`output/scan.rs`][scan-output], `schemas/` |

## Decisions to settle

1. The IPv4 and IPv6 probe sets (recommended: define each from the stack
   behaviors it distinguishes and document that reasoning; do not copy another
   tool's probe definitions or database).
2. The suitability conditions for each family (recommended: declare them with
   the probe set, and report every unmet condition as inconclusive).
3. How reference fingerprints are obtained (recommended: collect them from
   systems the project runs in isolated fixtures, each with provenance; import
   a third-party database only if it passes the
   [M1 license review][m1-data]).
4. How confidence is expressed (recommended: the ordinal approach chosen in
   [M8][m8], evaluated on the held-out set).
5. What happens when a platform cannot send part of the probe set (recommended:
   record capability per probe and report an incomplete set as inconclusive).
6. Whether OS identification is a stage of `scan` or a separate command
   (recommended: an explicit stage, consistent with [M8][m8]).

## Exit criteria

- [ ] IPv4 and IPv6 each have documented probe and evidence requirements.
- [ ] Known and held-out OS fixtures cover exact, near, and unknown matches,
      unavailable open or closed ports, filtered paths, NAT and intermediaries,
      and malformed evidence.
- [ ] Missing suitability conditions and ambiguous matches never produce an
      exact label.
- [ ] Service banners and passive TLS client fingerprints are never used as OS
      proof.
- [ ] The corpus has provenance records, and confidence is evaluated on the
      held-out set.
- [ ] The workflow preserves authorized scope, final-wire checks, timestamps,
      cancellation, evidence ceilings, and platform capability failures.
- [ ] Linux, macOS, and Windows support and runtime evidence are recorded
      independently.

[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m5]: m05-host-discovery.md
[m7]: m07-adaptive-scheduling.md
[m8]: m08-service-identification.md
[workflow-surface]: ../../crates/packetcraftr/src/lib.rs
[scan-limits]: ../../crates/packetcraftr/src/scan.rs
[scan-packets]: ../../crates/packetcraftr/src/scan/plan/packet.rs
[scan-report]: ../../crates/packetcraftr/src/scan/report.rs
[correlation]: ../../crates/packetcraftr/src/correlation.rs
[tcp-codec]: ../../crates/packetcraftr-core/src/protocol/transport/tcp.rs
[core-network]: ../../crates/packetcraftr-core/src/protocol/network.rs
[core-matcher]: ../../crates/packetcraftr-core/src/protocol/matcher.rs
[core-document]: ../../crates/packetcraftr-core/src/document.rs
[tls-analysis]: ../../crates/packetcraftr-core/src/analysis/tls.rs
[netio-transmit]: ../../crates/packetcraftr-netio/src/transmit.rs
[netio-capture]: ../../crates/packetcraftr-netio/src/capture.rs
[scan-output]: ../../crates/packetcraftr-cli/src/output/scan.rs
[nmap-os]: https://nmap.org/book/man-os-detection.html
