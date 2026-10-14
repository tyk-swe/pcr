# Scanner data policy

Bundled/shipped port, UDP payload, service match, OS fingerprint, and vendor data
requires per-source redistribution review under AGPL-3.0-only. **No third-party
source is presumed redistributable.** An unreviewed/incompatible source blocks
its dataset and the feature's acceptance, regardless of utility.

## Data kinds

| Kind | Review focus / current source |
| --- | --- |
| Port | Factual names/selections and creative payload bytes; original port catalog and UDP profiles |
| Service | Requests, literal matches, product/version metadata; original [service identification](service-identification.md) corpus and exclusions |
| OS | Original Linux Ethernet profiles in [OS provenance](../crates/packetcraftr/data/os-fingerprints.provenance.yaml) ([OS identification](os-identification.md)) |
| Vendor | Prefix assignments; none bundled, so discovery emits links without vendor labels |

Current sources: [port catalog](../crates/packetcraftr/data/port-catalog.provenance.yaml),
[UDP payloads](../crates/packetcraftr/data/udp-payloads.provenance.yaml),
[service probes](../crates/packetcraftr/data/service-probes.provenance.yaml), and
[sensitive exclusions](../crates/packetcraftr/data/service-exclusions.provenance.yaml).
Closed read-only request forms do not accept arbitrary operator outgoing bytes;
claims stay untrusted and independent fixtures define coverage.

## Per-data-set manifest

Use the [template](scanner-data-provenance-template.md) beside every bundled or
separate-asset dataset. Record:

1. Source/author and resolvable locator.
2. Retrieval date and upstream version.
3. Ordered reproducible transforms (including original authorship).
4. Exact license/terms and compatibility rationale or rejection; “open source”
   alone is no rationale.
5. Independent dataset version, separate from binary/output versions.
6. Named maintainer.
7. Refresh and license re-review procedure.
8. Coverage against declared fixtures, never another database's size.

## Source review

| Source | Disposition |
| --- | --- |
| Original project-authored fixtures and documents | **Acceptable.** Authored in this repository under AGPL-3.0-only. |
| Factual protocol constants independently authored from standards documents (RFCs, IEEE publications) | **Acceptable with citation.** The manifest records the standard and section; constants are authored into our own format, not copied from another project's tables. |
| Original factual product CPE mappings checked against the NIST NVD registry | **Acceptable with citation.** The service corpus manifest records the per-source review; original selections contain factual identifiers, no copied database or descriptions. Wildcard versions do not imply endorsement or a vulnerability finding. |
| IANA assignment registries (port numbers, protocol numbers, enterprise numbers, OUI-adjacent assignments) | **Candidate.** The IANA distribution and licensing terms must be reviewed for the specific registry before import; the review outcome is recorded per data set. |
| Nmap data or code (`nmap-services`, `nmap-service-probes`, `nmap-os-db`, `nmap-mac-prefixes`, or derivatives) | **Rejected.** The [NPSL][npsl] is not assumed AGPL-compatible, and no automatic compatibility is claimed; Nmap databases and probe/match content are not imported. |

Rejected sources retain their recorded reason. Candidates become acceptable only
with attached terms review; no silent reclassification. CPE labels/wildcard
versions assert neither verified identity nor vulnerability.

## Operator data

Runtime [UDP profiles](../crates/packetcraftr-core/src/document/udp_profiles.rs)
and service documents are bounded/validated at input, not bundled or presumed
redistributable. The project makes no license claim over operator input.

## Packaging

Embedded and separate assets both require completed source review, manifest,
and independent version. Port catalogs, UDP payloads, service probes/exclusions,
and OS fingerprints are embedded with adjacent provenance; no packaging choice
bypasses review.

## Versioning, maintenance, and coverage

Results name consumed dataset/version. Maintainers repeat review on changed
source/terms, then refresh fixtures and claims. Coverage citations describe
executed independent expectations, not imported database size or global prevalence.

[npsl]: https://nmap.org/npsl/
