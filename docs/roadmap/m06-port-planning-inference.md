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

## Implementation notes

- Selection lands in [`scan/selection.rs`][scan-selection]. `--ports` and
  `--exclude-ports` take terms: numeric ports and ranges, catalog names, and
  `@preset`, each optionally qualified `tcp:` or `udp:`. Inclusions expand in
  term order, then transport order, and deduplicate first-seen; every excluded
  endpoint is then removed, and only the remainder meets `--max-ports`. The
  result is `Request::endpoints`, a list of typed `ProbeEndpoint`s that
  replaces `transport` and `ports`. Planning, policy review, the probe and
  wire-byte budgets, and `scan --list` all read that one list.
- The catalog is a bounded core document,
  [`packetcraftr.port-catalog/v1`][catalog-document] (256 KiB, 2,048 entries,
  32 presets, names unique per transport), bundled as
  [`data/port-catalog.json`][catalog-data] beside its
  [provenance manifest][catalog-provenance]. Its 73 project-authored entries
  each cite the RFC that assigns or describes the port. The presets are `web`,
  `mail`, `name-services`, `infrastructure`, `legacy-services`, and `all`.
  [`scan::catalog`][scan-catalog] supplies each endpoint's `port_hint`.
- The curated payloads are a `packetcraftr.udp-profiles/v1` document,
  [`data/udp-payloads.json`][payload-data], beside its
  [manifest][payload-provenance]. It covers DNS root NS, mDNS service
  enumeration, RPC bind NULL, NTP client, SNMPv3 discovery, STUN binding, and
  CoAP resource discovery, each with a response check.
  [`profile::curated::merge`][scan-curated] applies them only to planned UDP
  endpoints, under `--curated-udp-payloads`.
- [`scan::inference`][scan-inference] draws one `Inference` per endpoint from
  its attempts' typed `Reply` values or connect outcomes. Each has a state
  (absent for operational failures), the deciding rule, and every attempt
  sequence in exactly one of `supporting`, `conflicting`, `unanswered`, or
  `failed`. ICMP echo endpoints get none. Attempt `classification` and the
  endpoint aggregate keep their v7 meaning.
- Frames that correlate with a probe but are not carried by its outcome are
  retained as `unattributed` evidence ([`Attribution`][scan-report]). That
  covers a superseded duplicate, a reply after the window, and a frame several
  probes match, in both serial and pipelined execution. They count toward
  `--max-undecoded` and the shared evidence byte budget.
- [`scan::method::select`][scan-method] resolves `--method raw|tcp-connect|auto`
  (`--connect` aliases `tcp-connect`) against
  [`NativeCapability::check`][netio-unsupported], which answers from the
  build's capability cfgs without a native call. An explicit method is never
  replaced. Selection never fails for missing packet I/O, so in a build
  without it a raw scan is still reviewed by policy first, then fails with the
  raw engine's capability error.
- Results ship in `packetcraftr.output/v8` ([schema][schema-v8],
  [migration][migration], [compatibility][compatibility-v8]). v8 adds a `plan`
  record: the requested and selected method with the reason, the
  `port_catalog` and curated payload data sets, the excluded-endpoint count,
  and the applied and overridden curated ports. It also adds `port_hint` and
  `inference` on endpoints, `unattributed` frames, `endpoint` and
  `connect_endpoint` stream records before `complete`, and the list `ports`
  record. The [evidence model][evidence-inference] carries the rule table and
  the Nmap mapping.
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

## Change map

| Change | Start here |
| --- | --- |
| Port selection, exclusions, typed protocols | [`scan/request.rs`][scan-request], [`commands/scan/arguments.rs`][scan-args] |
| Catalog and payload documents | core [`document/udp_profiles.rs`][udp-document] as the bounded-document precedent, [`scan/profile.rs`][udp-profiles] |
| Combined plans and endpoint identity | [`scan/plan.rs`][scan-plan], [`scan/plan/packet.rs`][scan-packets] |
| Inference | [`scan/evidence.rs`][scan-evidence], [`scan/report.rs`][scan-report] |
| Method planning | [`commands/scan.rs`][scan-command], [`scan/connect/engine.rs`][connect-engine] |
| Published records and contract | [`output/scan.rs`][scan-output], [`output/contract.rs`][output-contract], `schemas/`, `docs/migration-unreleased.md` |

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
- **Runtime evidence ([M3][m3]): native replies faster than the send call
  are not correlated.** In the native run the target kernel's SYN/ACK, RST,
  and ICMP port-unreachable replies arrived about 30 µs after each probe,
  before `send()` returned. The
  shared rule that a capture inside the submission interval is not proven
  post-send ([`transmit::Timing`][netio-transmit]) discards them in every
  workflow, so those endpoints inferred silence. The revision before M6
  behaves the same, and slower replies such as the UDP echo correlate.
  Deciding what such frames prove belongs with native validation in
  [M3][m3]; M6 retains no new class of frame for it. Until then no native
  scenario can show TCP or ICMP-error inference, and nothing has run on macOS
  or Windows.

[m1]: m01-claims-evidence.md
[m1-vocabulary]: m01-claims-evidence.md#m11-evidence-vocabulary
[m1-data]: m01-claims-evidence.md#m12-scanner-data-policy
[m2]: m02-ground-truth-benchmarks.md
[m3]: m03-native-validation.md
[m5]: m05-host-discovery.md
[scan-selection]: ../../crates/packetcraftr/src/scan/selection.rs
[scan-catalog]: ../../crates/packetcraftr/src/scan/catalog.rs
[scan-curated]: ../../crates/packetcraftr/src/scan/profile/curated.rs
[scan-inference]: ../../crates/packetcraftr/src/scan/inference.rs
[scan-method]: ../../crates/packetcraftr/src/scan/method.rs
[catalog-document]: ../../crates/packetcraftr-core/src/document/port_catalog.rs
[catalog-data]: ../../crates/packetcraftr/data/port-catalog.json
[catalog-provenance]: ../../crates/packetcraftr/data/port-catalog.provenance.yaml
[payload-data]: ../../crates/packetcraftr/data/udp-payloads.json
[payload-provenance]: ../../crates/packetcraftr/data/udp-payloads.provenance.yaml
[netio-unsupported]: ../../crates/packetcraftr-netio/src/unsupported.rs
[netio-transmit]: ../../crates/packetcraftr-netio/src/transmit.rs
[schema-v8]: ../../schemas/packetcraftr.output.v8.schema.json
[migration]: ../migration-unreleased.md
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
