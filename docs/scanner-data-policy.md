# Scanner data policy

This policy governs data the scanner bundles or ships beside the binary: port
catalogs, service probes and match patterns, OS fingerprints, and vendor
prefixes. It is the [M1][m1] data policy; [M6][m6-catalog] applies it to the
first imported data set, and no scanner feature that consumes bundled data is
complete before its source passes this review.

PacketcraftR is licensed AGPL-3.0-only. Bundled data must be reviewed for
redistribution compatibility before it is imported; **no third-party source is
presumed redistributable**, and an incompatible or unreviewed source blocks the
data set regardless of how useful it is.

## Data kinds

| Kind | Used by | Contents |
| --- | --- | --- |
| Port data | Port planning and named selections ([M6][m6-catalog]) | Port-to-service-name catalog, curated selection lists, UDP probe payloads |
| Service data | Service/version identification ([M8][m8], [M9][m9]) | Probe payloads, response match patterns, product/version metadata |
| OS data | OS identification ([M10][m10]) | Stack fingerprints and match rules |
| Vendor data | Discovery enrichment ([M5][m5]); none bundled, so host records publish link addresses without vendor labels | MAC/OUI prefix assignments |

The kind decides the review focus (for example, payload bytes are creative
content in a way bare port numbers are not), but every kind carries the same
manifest and review requirements.

## Per-data-set manifest

Every bundled or shipped data set carries a manifest written from the
[provenance template][template], recording:

1. **Source.** Where the data came from: upstream project, document, or
   fixture author, with a URL or other resolvable locator.
2. **Retrieval date.** When the source content was obtained.
3. **Transforms.** Every transformation applied between the source and the
   shipped form (selection, reformatting, merging, compilation), so a reviewer
   can reproduce the shipped artifact from the recorded source.
4. **License compatibility rationale.** The source's license or terms, and the
   reasoning that makes redistribution under or alongside AGPL-3.0-only sound
   — or the recorded rejection. "The tool is open source" is not a rationale.
5. **Independent version.** The data set's own version, separate from the
   binary version and the output contract, so a published result can name the
   exact data that produced it.
6. **Maintainer.** The named owner responsible for the data set.
7. **Refresh procedure.** How upstream changes are pulled, re-reviewed, and
   re-tested, including what re-review a refresh requires.
8. **Coverage.** What the data set covers, stated against declared fixtures —
   never against the size of another tool's database.

## Source review

Each source is reviewed per data kind before import, and the outcome is
recorded in the manifest:

| Source | Disposition |
| --- | --- |
| Original project-authored fixtures and documents | **Acceptable.** Authored in this repository under AGPL-3.0-only. |
| Factual protocol constants independently authored from standards documents (RFCs, IEEE publications) | **Acceptable with citation.** The manifest records the standard and section; constants are authored into our own format, not copied from another project's tables. |
| IANA assignment registries (port numbers, protocol numbers, enterprise numbers, OUI-adjacent assignments) | **Candidate.** The IANA distribution and licensing terms must be reviewed for the specific registry before import; the review outcome is recorded per data set. |
| Nmap data or code (`nmap-services`, `nmap-service-probes`, `nmap-os-db`, `nmap-mac-prefixes`, or derivatives) | **Rejected.** The [NPSL][npsl] is not assumed AGPL-compatible, and no automatic compatibility is claimed; Nmap databases and probe/match content are not imported. |

A rejected source stays rejected with its reason recorded here, not silently
revisited; a candidate becomes acceptable only with the terms review attached
to the manifest.

## Operator data

Data the operator supplies at run time — such as
[UDP profile documents][udp-document] — is never bundled and is never presumed
licensed for redistribution. Bounded document parsers validate it at the input
boundary; the project makes no claim on it.

## Packaging

A data set may ship inside the binary or as a separate release asset. Both
forms are permitted **only after the per-source review passes**; the choice is
made per data set with its first import ([M6][m6-catalog] decides the port
catalog's form). Separate assets still carry the same manifest and version.

[M6][m6-catalog] bundles its two data sets inside the library: the
[port catalog][port-catalog] and the [curated UDP payloads][udp-payloads], each
beside its provenance manifest.

## Versioning, maintenance, and coverage

- Results that consume bundled data name the data set and its independent
  version, so two runs over the same scan input can be distinguished by the
  data that produced them.
- The named maintainer owns refreshes; a refresh re-runs the license review
  when the upstream version or its terms change.
- Coverage claims cite the fixtures the data set was exercised against.
  Database-size comparisons with other tools are not acceptance criteria.

[m1]: roadmap/m01-claims-evidence.md
[m5]: roadmap/m05-host-discovery.md
[m6-catalog]: roadmap/m06-port-planning-inference.md#m61-port-catalog-and-named-selections
[m8]: roadmap/m08-service-identification.md
[m9]: roadmap/m09-tls-services-corpus.md
[m10]: roadmap/m10-os-identification.md
[npsl]: https://nmap.org/npsl/
[port-catalog]: ../crates/packetcraftr/data/port-catalog.provenance.yaml
[template]: scanner-data-provenance-template.md
[udp-document]: ../crates/packetcraftr-core/src/document/udp_profiles.rs
[udp-payloads]: ../crates/packetcraftr/data/udp-payloads.provenance.yaml
