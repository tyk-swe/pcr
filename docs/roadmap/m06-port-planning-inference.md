# M6: Port planning and state inference

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M1][m1] | [M7][m7], [M11][m11], [M12][m12], [M13][m13] |

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

## Implementation notes

One typed endpoint list drives authorization, planning, budgets, list mode, and
execution. Port inclusions expand in term/transport order with first-seen
deduplication; exclusions apply before the port ceiling. TCP/UDP endpoints on the
same number stay distinct; ICMP is portless.

The [catalog][catalog-data] and [curated payloads][payload-data] are independently
versioned documents with [catalog][catalog-provenance] and
[payload][payload-provenance] provenance. Catalog labels are hints, not identified
services; curated UDP requests require explicit opt-in and apply only to planned
endpoints. See [inference rules][evidence-inference] for every attempt's partition
into supporting/conflicting/unanswered/failed evidence and retained unattributed
frames.

Explicit methods never fall back. Automatic selection reads build capability,
not runtime privilege; missing raw I/O still fails through policy-first engine
admission. Output first gained the plan, hints, inference, unattributed frames,
and endpoint events in v8; current v12 retains them under the
[consumer policy][compatibility-v8].

- A native Linux run used two throwaway network namespaces joined by a veth
  pair on TEST-NET-1, with checksum offload disabled. It scanned
  `tcp:18080-18082` and three UDP ports in one plan, excluding `tcp:18081`.
  The excluded endpoint was never sent, and udp/18081 stayed a separate
  endpoint. A UDP echo service inferred `open` (`udp.reply`, frames retained),
  and bound or closed silent UDP ports inferred `open_or_filtered`. The method
  published `raw`.

### Known limits

- **Frequency-ranked "top ports" are not offered.** No port-frequency source
  is acceptable under the [data policy][m1-data] yet, so the catalog is a
  curated named list (decision 1).
- **Automatic selection reads build capability, not run-time privilege.** It
  checks capture and transmission in the requested link mode, but a
  capture-capable build run without packet privileges still selects `raw` and
  fails at execution with a capability error.
- **Discovery ports follow the same selection.** [M5][m5] discovery takes
  `--discovery-ports` terms through `scan::select_endpoints` with the scan's
  `--exclude-ports`, so discovery never probes an excluded port either.

## Decisions

Settled at M6 with the recommended positions:

1. **The catalog is a curated named list with no frequency claim.** No
   port-frequency source is acceptable under the [M1 data policy][m1-data]:
   IANA registries await terms review and Nmap data is rejected. The bundled
   catalog is project-authored, cites the RFC behind each entry, and offers
   topical presets instead of top-N ports.
2. **There is no default selection.** A TCP or UDP scan without `--ports` is a
   usage error, and `@all` is how an operator asks for the whole catalog.
3. **The inferred-state labels are PacketcraftR's own**: `open`, `closed`,
   `filtered`, `open_or_filtered`, and `unknown`, with the Nmap mapping
   documented in the [evidence model][evidence-inference]. There is no
   idle-scan `closed|filtered` label, and no `unfiltered` until [M12][m12] adds
   the ACK and window scans that produce it.
4. **Inference ships in `packetcraftr.output/v8`**, introduced once for every
   command with its schema, examples, conformance tests, and migration notes.
   v6 and v7 stay frozen.
5. **Automatic method selection happens only when requested** with
   `--method auto`. The default stays the raw method.
6. **The operator profile wins** over a curated payload for the same port, and
   the plan lists that port under `overridden`.

## Exit criteria

- [x] State and reason matrices cover replies, silence, ICMP errors,
      duplicates, contradictory attempts, malformed packets, loss, and
      reordering. The [inference tests][inference-tests] run each reply under
      each rule table and cover silence, ICMP errors, duplicates,
      contradictions, and delivery order. The [pipeline contracts][pipeline-contracts]
      show malformed frames and lost replies inferring silence, and duplicate
      and late frames retained through both executors.
- [x] Socket deadline and capacity failures are never reported as target port
      states. Connect `local_error` and `deadline_expired` infer no state under
      `operational_failure`, and exhausted connect capacity is waited for and
      [asserted][connect-capacity] not to produce a state.
- [x] TCP and UDP endpoints on one address and port stay distinct in plans,
      evidence, and output. Correlation and the collector key by `(address,
      transport, port, interface)`, and a [pipeline contract][pipeline-contracts]
      scans tcp/53 and udp/53 under one budget into two endpoints with
      different states.
- [x] Port-name hints are published as hints and never as service
      identification. `port_hint` sits beside `inference` and is documented as
      a catalog hint, and a matched curated check remains an `application`
      check result.
- [x] No stage, including discovery, probes an excluded port. Exclusions
      remove endpoints before the request exists, and a
      [matrix contract][selection-matrix] checks the sent wire. [M5][m5]
      discovery ports pass through the same selection and exclusions.
- [x] Conflicting and late or unattributed evidence is retained beside each
      inference, as `conflicting` and `unanswered` sequences and as
      `unattributed` frames carrying their attribution and probe.
- [x] An explicitly requested raw method is never replaced by an ordinary
      connection, the selected method is published, and no wire evidence is
      fabricated for socket observations. See the [method tests][method-tests]
      and the [CLI contracts][planning-contracts]: raw fails in a build
      without packet I/O while the listener never sees a connection, and
      connect probes carry no frame.
- [x] The catalog and curated payloads have provenance records, and results
      name the data version used. The [catalog][catalog-tests] and
      [curated payload][curated-tests] tests check the manifests, and results
      carry `plan.port_catalog` and `plan.curated_udp_payloads.data_set`.
- [x] Contract changes follow the [compatibility policy][compatibility]. v8 is
      a new family, conformance still validates the frozen v6 and v7 schemas,
      and the examples and the reference consumer move to v8.

## Blockers

Every exit criterion has fixture evidence, but the roadmap [close
gates][close-gates] keep M6 `In progress`:

- **Ground truth ([M2][m2]).** Inference publishes scanner results, so the
  mixed TCP/UDP, silent-UDP, and contradictory-attempt scenarios need entries
  in the comparison corpus with independent expected outcomes. The injected
  scanner fixture covers attempt classifications only.
- **Runtime evidence ([M3][m3]).** The original completion-marker race
  (native SYN/ACK, RST, and ICMP errors arriving before `send()` returned) is
  fixed by M5's submission-start eligibility boundary. Immediate dual-stack
  discovery fixtures now exercise these replies. This is not precise wire
  departure or identity proof, and does not substitute for M6's own exact-revision
  native port-inference acceptance on every supported platform. See
  [M5's native evidence route](m05-host-discovery.md#independent-discovery-corpus-and-runtime-route).

[m1]: m01-claims-evidence.md
[m1-vocabulary]: m01-claims-evidence.md#m11-evidence-vocabulary
[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m2]: m02-ground-truth-benchmarks.md
[m3]: m03-native-validation.md
[m5]: m05-host-discovery.md
[catalog-data]: ../../crates/packetcraftr/data/port-catalog.json
[catalog-provenance]: ../../crates/packetcraftr/data/port-catalog.provenance.yaml
[payload-data]: ../../crates/packetcraftr/data/udp-payloads.json
[payload-provenance]: ../../crates/packetcraftr/data/udp-payloads.provenance.yaml
[compatibility-v8]: ../consumer-compatibility.md#output-family-v8
[evidence-inference]: ../scanner-evidence.md#port-inference
[inference-tests]: ../../crates/packetcraftr/src/scan/inference/tests.rs
[pipeline-contracts]: ../../crates/packetcraftr/tests/integration/scan_pipeline_contracts.rs
[connect-capacity]: ../../crates/packetcraftr/tests/connect_scan_contracts.rs
[selection-matrix]: ../../crates/packetcraftr/tests/integration/port_selection_matrix.rs
[method-tests]: ../../crates/packetcraftr/src/scan/method/tests.rs
[planning-contracts]: ../../crates/packetcraftr-cli/tests/integration/port_planning_contracts.rs
[catalog-tests]: ../../crates/packetcraftr/src/scan/catalog/tests.rs
[curated-tests]: ../../crates/packetcraftr/src/scan/profile/curated/tests.rs
[m7]: m07-adaptive-scheduling.md
[m8]: m08-service-identification.md
[m11]: m11-scan-informed-traceroute.md
[m12]: m12-tcp-diagnostic-scans.md
[m13]: m13-sctp-ip-protocol.md
[close-gates]: README.md#close-gates
[compatibility]: ../consumer-compatibility.md
