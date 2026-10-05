# M6: Port planning and state inference

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M1][m1] | [M7][m7], [M11][m11], [M12][m12], [M13][m13] |

PacketcraftR scans the numeric ports it is given, over one transport per
request, and reports what each probe observed. That is faithful but leaves the
scanner work to the operator: there are no named or common-port selections, no
way to exclude a port, no combined TCP and UDP plan, and no conclusion drawn
from a set of attempts beyond the highest-ranked classification. A UDP port
that stays silent is reported as a timeout, which is true and not yet an
inference.

This milestone adds scanner-oriented port selection and a separate,
scan-dependent inference layer in the [M1][m1-vocabulary] vocabulary, while
keeping every attempt outcome visible.

## Outcome

- Ports can be selected by versioned catalog preset or by name, and excluded
  explicitly.
- Curated UDP payloads cover a bounded set of ports.
- One plan can combine TCP and UDP selections under one operation budget.
- Each endpoint has an inferred state with the rule and evidence that produced
  it, beside its recorded attempt outcomes.
- The scan method can be chosen from available capability without changing an
  explicitly requested method.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| Port selection | `--ports` takes numeric ports and inclusive ranges with first-seen deduplication, bounded by `--max-ports` (default 1,024); TCP and UDP require explicit ports ([request][scan-request], [arguments][scan-args]) | Named and frequency-ranked ports, fast and top-port selections, exclusions ([port specification][nmap-ports]) |
| UDP payloads | Empty or one explicit payload; [UDP profiles][udp-profiles] supply per-port requests and response checks from an operator [document][udp-document] | Protocol-specific payloads for common ports ([scan techniques][nmap-techniques]) |
| Protocols per plan | One transport per [request][scan-request] | TCP, UDP, and SCTP selections can coexist ([scan techniques][nmap-techniques]) |
| States | [`Classification`][scan-report] of `open`, `closed`, `filtered`, `unreachable`, `unknown`, `timeout`, with ranked endpoint aggregation over [raw observations][scan-evidence] | Scan-dependent states including `open\|filtered` and `unfiltered` ([state meanings][nmap-states]) |
| Method choice | `--connect` is explicit; no automatic method selection ([scan command][scan-command]) | Connect scan is chosen when raw SYN is unavailable ([scan techniques][nmap-techniques]) |

## Invariants

- Port-name hints are hints. A name attached to a port number is not service
  identification.
- Endpoint identity includes the transport. TCP and UDP on one address and port
  never merge.
- An inference never replaces the attempt outcomes it was drawn from.
- A socket observation is never published as wire evidence.

## Scope

### M6.1 Port catalog and named selections

- A versioned catalog that supports common-port presets and selection by name.
- The catalog is data under the [M1 data policy][m1-data]: it has a provenance
  record and its version appears in results that used it.
- Catalog selections expand through the same `--max-ports` and probe bounds as
  numeric selections.

### M6.2 Port exclusions

- Explicit port exclusions, applied after expansion and before any probe is
  planned.
- Exclusions bind every stage of the operation. Discovery cannot silently use
  an excluded port.

### M6.3 Curated UDP payloads

- A bounded, curated set of UDP payloads keyed by port, built on the existing
  UDP profile building blocks.
- A matched response check remains a configured check that matched, not
  product identity; that belongs to [M8][m8].

### M6.4 Mixed TCP/UDP plans

- Typed protocol selections so one request can carry TCP and UDP ports.
- One operation budget covers the combined plan.
- Plans, evidence, and output key endpoints by address, transport, and port.

### M6.5 Inferred states and reasons

- A scan-dependent inferred state for each endpoint, with the rule that
  produced it, including the ambiguous case of a silent UDP port.
- The recorded outcome of every attempt stays beside the inference.
- Conflicting attempts and late or unattributed evidence are retained rather
  than erased to force a single answer.
- Operational failures such as a socket deadline or exhausted capacity are
  reported as failures, not as port states.

### M6.6 Capability-aware method planning

- The plan can select a scan method from the capabilities the build and
  platform provide, and publishes which method it selected.
- An explicitly requested raw method is never silently replaced by an ordinary
  connection; it fails with a capability error instead.

## Change map

| Change | Start here |
| --- | --- |
| Port selection, exclusions, typed protocols | [`scan/request.rs`][scan-request], [`commands/scan/arguments.rs`][scan-args] |
| Catalog and payload documents | core [`document/udp_profiles.rs`][udp-document] as the bounded-document precedent, [`scan/profile.rs`][udp-profiles] |
| Combined plans and endpoint identity | [`scan/plan.rs`][scan-plan], [`scan/plan/packet.rs`][scan-packets] |
| Inference | [`scan/evidence.rs`][scan-evidence], [`scan/report.rs`][scan-report] |
| Method planning | [`commands/scan.rs`][scan-command], [`scan/connect/engine.rs`][connect-engine] |
| Published records and contract | [`output/scan.rs`][scan-output], [`output/contract.rs`][output-contract], `schemas/`, `docs/migration-unreleased.md` |

## Decisions to settle

1. The source of the catalog's port ranking (recommended: decide under the
   [M1 data policy][m1-data]; if no acceptable frequency source exists, ship a
   curated named list and make no frequency claim).
2. Whether a TCP or UDP scan gets a default selection when no ports are given
   (recommended: no; a preset must be requested, so a scan's scope is never
   implicit).
3. The inferred-state labels (recommended: PacketcraftR's own labels from
   [M1][m1-vocabulary], with a documented mapping to Nmap's for comparison, and
   no idle-specific label).
4. The contract family that carries inference (recommended: the new family
   settled in [M1][m1], introduced once here with its schema, examples,
   conformance tests, and migration notes).
5. Whether method selection is automatic by default (recommended: only when the
   request asks for it; the default keeps today's explicit methods).
6. How a curated payload and an operator profile for the same port combine
   (recommended: the operator profile wins and the override is visible).

## Exit criteria

- [ ] State and reason matrices cover replies, silence, ICMP errors,
      duplicates, contradictory attempts, malformed packets, loss, and
      reordering.
- [ ] Socket deadline and capacity failures are never reported as target port
      states.
- [ ] TCP and UDP endpoints on one address and port stay distinct in plans,
      evidence, and output.
- [ ] Port-name hints are published as hints and never as service
      identification.
- [ ] No stage, including discovery, probes an excluded port.
- [ ] Conflicting and late or unattributed evidence is retained beside each
      inference.
- [ ] An explicitly requested raw method is never replaced by an ordinary
      connection, the selected method is published, and no wire evidence is
      fabricated for socket observations.
- [ ] The catalog and curated payloads have provenance records, and results
      name the data version used.
- [ ] Contract changes follow the [compatibility policy][compatibility].

[m1]: m01-claims-evidence.md
[m1-vocabulary]: m01-claims-evidence.md#m11-evidence-vocabulary
[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m7]: m07-adaptive-scheduling.md
[m8]: m08-service-identification.md
[m11]: m11-scan-informed-traceroute.md
[m12]: m12-tcp-diagnostic-scans.md
[m13]: m13-sctp-ip-protocol.md
[compatibility]: ../consumer-compatibility.md
[scan-request]: ../../crates/packetcraftr/src/scan/request.rs
[scan-plan]: ../../crates/packetcraftr/src/scan/plan.rs
[scan-packets]: ../../crates/packetcraftr/src/scan/plan/packet.rs
[scan-evidence]: ../../crates/packetcraftr/src/scan/evidence.rs
[scan-report]: ../../crates/packetcraftr/src/scan/report.rs
[udp-profiles]: ../../crates/packetcraftr/src/scan/profile.rs
[connect-engine]: ../../crates/packetcraftr/src/scan/connect/engine.rs
[udp-document]: ../../crates/packetcraftr-core/src/document/udp_profiles.rs
[scan-command]: ../../crates/packetcraftr-cli/src/commands/scan.rs
[scan-args]: ../../crates/packetcraftr-cli/src/commands/scan/arguments.rs
[scan-output]: ../../crates/packetcraftr-cli/src/output/scan.rs
[output-contract]: ../../crates/packetcraftr-cli/src/output/contract.rs
[nmap-ports]: https://nmap.org/book/man-port-specification.html
[nmap-techniques]: https://nmap.org/book/man-port-scanning-techniques.html
[nmap-states]: https://nmap.org/book/man-port-scanning-basics.html
