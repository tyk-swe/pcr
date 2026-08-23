# PacketcraftR roadmap

Status: pre-1.0 planning  
Last reviewed: 2026-08-23

## Purpose

PacketcraftR 1.0 will stabilize the program's existing packet construction,
dissection, capture, analysis, and policy-gated live-networking claims. It is
not a protocol-count milestone.

Work belongs in the committed roadmap only when it does at least one of the
following:

- fixes a demonstrated correctness or live-safety defect;
- makes an existing public contract usable and stable; or
- supplies evidence that an advertised workflow works within declared limits.

Everything else remains a candidate until a concrete user workflow, measured
limit, and maintainer are known.

## Todo list

- [ ] [Define the 1.0 contract](#define-the-10-contract).
- [ ] [Authorization of non-interface-owned
  sources](#authorization-of-non-interface-owned-sources).
- [ ] [Canonical integrity classification](#canonical-integrity-classification).
- [ ] [Registry extension](#registry-extension).
- [ ] [Public API and serialized contracts](#public-api-and-serialized-contracts).
- [ ] [Performance-sensitive contracts](#performance-sensitive-contracts).
- [ ] [Confidence gate](#confidence-gate).
- [ ] [Decisions that do not imply
  implementation](#decisions-that-do-not-imply-implementation).

## Define the 1.0 contract

Before the first release candidate, decide and document:

- the supported crates, Cargo feature profiles, operating systems, and
  architectures;
- the Rust API surface covered by semantic-versioning guarantees;
- the compatibility policy for packet documents, output documents, NDJSON
  streams, CLI arguments, and exit codes;
- representative construction, dissection, offline-analysis, capture, and
  multi-packet live workflows; and
- measurable time, memory, queue, and throughput ceilings for those workflows.

Known limitations may remain in 1.0 when they are explicit and do not violate a
supported contract.

## Release blockers

### Authorization of non-interface-owned sources

Packet construction may retain an explicit source IP or MAC address that is
not owned by the selected interface. That capability is useful for authorized
packet testing, but the high-level traffic policy does not distinguish it from
ordinary interface-owned source selection.

Acceptance criteria:

- unspecified sources continue to materialize from the selected route;
- explicit interface-owned sources require no additional permission;
- a non-interface-owned outer IP or Ethernet source is denied by default;
- intentional source spoofing has one dedicated, explicit policy opt-in;
- the check occurs after interface selection and before neighbor discovery,
  capture, or transmission; and
- documentation describes the same source-ownership behavior the native
  boundary enforces.

CIDR policy, a universal rate limiter, and additional policy languages are not
part of this blocker. Add them only for a workflow that cannot express its
safety boundary with the existing destination and finite-operation controls.

### Canonical integrity classification

Live response correlation currently recognizes checksum failures by searching
diagnostic-code text. External diagnostic names can therefore accidentally
change correlation behavior.

Acceptance criteria:

- integrity rejection uses one canonical structured predicate or exact
  classification;
- every built-in checksum diagnostic follows that classification;
- unrelated external diagnostic names cannot trigger integrity rejection; and
- known checksum-offload limitations are documented rather than represented as
  certainty the capture cannot provide.

A repository-wide diagnostic taxonomy, byte-range retrofit, and new capture
provenance model are separate work.

## Contract freeze

### Registry extension

Choose one supported model for external codecs before 1.0. The preferred
minimal contract is a built-in-seeded registry builder that accepts additional
codecs, matchers, bindings, and filter fields before final validation.

Acceptance criteria:

- there is one canonical way to extend the built-in registry;
- one external-consumer example constructs, dissects, and filters a custom
  protocol alongside built-ins; and
- unsupported extension behavior is stated explicitly.

Dynamic plugins, a plugin ABI, and a general runtime `decode-as` system are not
required.

### Public API and serialized contracts

- Remove or privatize public items that are not intended commitments.
- Document the invariants and failure behavior of the remaining supported API.
- Add runnable examples for core packet mechanics, offline analysis, injected
  providers, and native composition.
- Record a public-API baseline and check later releases for unintended semantic
  versioning breaks.
- Freeze output-v1 and packet-v1 only after their compatibility rules and
  immutable publication locations are defined.
- Decide crates.io publication separately from technical readiness.

Missing-documentation warning counts are an audit signal, not an acceptance
target. Pruning precedes documentation.

### Performance-sensitive contracts

Measure representative workloads before freezing codec ownership and native
provider traits:

- dissection and filtering of a large capture;
- TCP reassembly under reordered and retransmitted input;
- live capture startup, delivery, loss accounting, and shutdown; and
- scan, replay, and live-fuzz transmission over multiple packets.

Introduce zero-copy decoded fields or operation-scoped transmission sessions
only when the measurements miss the declared ceilings. Do not add arenas,
global handle caches, async runtimes, or specialized packet backends without
that evidence.

## Confidence gate

The existing deterministic test matrix remains the baseline. Before 1.0, add:

- coverage-guided fuzz targets for PCAP/PCAPNG framing and the generic
  dissector;
- a small sanitized corpus produced by independent capture implementations;
- invariants covering panic freedom, bounded allocation, exact malformed-byte
  preservation, and transactional errors;
- a privileged Linux network-namespace smoke path for route, ARP/NDP, capture,
  send, timeout, and cleanup; and
- scheduled runtime smoke evidence for every macOS and Windows native variant
  distributed as a release artifact.

Add dedicated reassembly, document, expression, and filter fuzz targets only
after the first targets are stable and their coverage shows a remaining trust
boundary.

## Decisions that do not imply implementation

These semantics must be named or documented before 1.0, but their current
behavior is not automatically defective:

- whether `tcp.stream` identifies an endpoint flow or one TCP connection
  generation;
- whether fragmented traffic is supported by `follow` and `expert` or remains
  an explicit limitation;
- which analyses require timestamps and how timestamp-less PCAPNG records
  fail;
- whether successful early stop and CLI cancellation are part of the stable
  analysis contract; and
- whether the libraries are distributed through crates.io or through source
  dependencies.

If clean Ctrl-C behavior is selected for 1.0, implement it first at workflow
loops and native capture shutdown. Do not add cancellation parameters to
providers that have no interrupt mechanism.

## Post-1.0 candidates

The following are candidates, not commitments, and are ordered only after
usage evidence exists:

- IP-fragment reassembly followed by re-dissection and provenance-preserving
  flow analysis;
- capture direction and buffer controls, multi-interface capture, and richer
  PCAPNG metadata interpretation;
- DNS-over-TCP when the DNS command is intended to behave as a general
  resolver rather than a UDP packet probe;
- deeper TCP, ICMP, NDP, DNS, DHCP, and LLDP models and expert findings;
- large-capture indexing and finding-driven export; and
- async adapters or higher-throughput native backends when stable benchmarks
  demonstrate a need.

Additional application, routing, wireless, tunnel, or encrypted-protocol
support requires a named workflow and maintainer. Protocol breadth alone does
not justify inclusion.

## Non-goals without new evidence

- dynamic plugin loading or a stable plugin ABI;
- a daemon, configuration framework, or remote-control service;
- an async runtime dependency in the portable core;
- AF_XDP, eBPF, packet-ring, or similar backend work;
- silent capture transcoding or metadata normalization; and
- protocol parity with Wireshark, Scapy, or a complete operating-system network
  stack.

## 1.0 exit criteria

PacketcraftR is ready for a 1.0 release candidate when:

- all three release blockers are closed;
- supported Rust and serialized contracts are explicit and compatibility
  checked;
- one external codec works through the supported registry-extension path;
- representative workloads satisfy their documented resource ceilings;
- focused fuzzing and independent corpora exercise the primary untrusted-input
  boundaries;
- every distributed native variant has current runtime smoke evidence; and
- every remaining limitation is documented without implying required
  follow-up work.

## Maintaining this roadmap

Move a candidate into the committed roadmap only with an issue that states its
operator workflow, ownership, public-contract impact, resource and safety
bounds, and executable acceptance criteria. Record completed user-visible work
in the changelog and remove it from this file; the roadmap is not a second
release history.
