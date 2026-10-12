# OS identification

`identify-os` collects a finite, original TCP/ICMP fingerprint from one numeric
IPv4 or IPv6 target. Supply a known open TCP port and a distinct known closed
TCP port; the workflow verifies both before collecting the remaining probes.
Use targets covered by your authorization and destination policy.

```sh
packetcraftr --output json identify-os 192.0.2.2 \
  --open-port 443 --closed-port 43125 --interface eth0 --link-mode layer2
packetcraftr --output ndjson identify-os 2001:db8::2 \
  --open-port 443 --closed-port 43125 --attempts 1 --timeout-ms 500
```

Interface names and endpoint roles are examples. Existing route, scoped-IPv6,
preferred-source, and numeric policy options apply. Native raw/capture capability
and privileges are required; unavailable capabilities produce typed errors.

## Observations and candidates

Output/v14 preserves exact sent packets, retained response frames, probe/attempt
identities, timing, omissions, additional responses, and diagnostics. Observations
include TCP flags, window, ordered options, MSS, scale, SACK and timestamp support.
Raw sequence, timestamp, IPv4 ID/flags, and TTL/hop-limit values remain visible;
TTL does not become a guessed initial TTL or OS label.

The matcher requires suitable SYN/ACK responses to both open-port SYN forms and
a correlated RST/ACK from the closed port. Echo is optional. Every retained reply
to a relevant probe participates; contradictions remain visible. Late replies,
unrelated traffic, router errors, and invalid checksums cannot establish a
fingerprint. Timestamp replies must echo the authored value when present.

| Outcome | Meaning |
| --- | --- |
| `matched` | Fully satisfied signatures qualify one family. |
| `ambiguous` | Fully satisfied signatures qualify competing families. |
| `unknown` | Suitable required evidence matches no signature. |
| `inconclusive` | Required evidence is missing, unsuitable, contradictory, or retention is incomplete. |

Candidates cite signature, corpus/version, reference, and supporting observation
indices into the terminal observations array, starting at zero. Ranking uses predicate count then signature identifier and retains
competing families. `qualified` is ordinal evidence qualification, not probability,
authenticated identity, or an OS release claim. NAT, firewalls, proxies, custom
stacks, path MTU, and TCP configuration can change or imitate observations.

`complete` describes execution and retained evidence. An unsuitable target can
complete with an inconclusive result. Cancellation, expiry, native failure, and
output failure follow existing typed errors; an NDJSON error terminal preserves
earlier published records. Aggregate errors do not claim a completed fingerprint.

## Probe set and bounds

`packetcraftr.os-probes/v1` defines these independently authored packets:

| Probe | Authored packet |
| --- | --- |
| `open_syn` | SYN, window 65535, MSS 1460, SACK-permitted, NOP, scale 7; explicit zero alignment. |
| `closed_syn` | SYN to the closed port, window 65535, no options. |
| `timestamp_syn` | Open SYN options plus an operation-specific timestamp. |
| `echo` | ICMP echo with operation-specific correlation bytes. |

Selected replies with exact SYN/ACK flags receive bounded RST/ACK cleanup with
the exact sequence relationship, including an open port supplied as closed.
Unsuitable port evidence stops additional fingerprint probes. Each attempt has a distinct identity. Preparation, probes, and
cleanup share deadline, destination policy, final-wire authorization, packet/byte
budgets, and pacing. Native kernels can additionally generate their own replies
to raw traffic; capture context matters.

Defaults are two attempts per probe, one-second windows, ten packets per second,
a 30-second operation deadline, and 32 workflow transmissions. Hard ceilings are
three attempts, 32 transmissions, 30 seconds, 256 retained capture frames, 1 MiB
retained capture bytes, and 4096 bytes per captured frame. Sent receipts are
separately bounded by transmission and wire-byte ceilings. Neighbor preparation
allows one request and shares operation retention; no hidden retry follows.
Capture overflow fails execution. Retention exhaustion withholds qualification.

## Corpus and library

Bundled `project-os-fingerprints` 1.0.0 contains two qualified Linux signatures for
the recorded 1500-byte Ethernet IPv4/IPv6 profiles. Original Linux 7.0.0-38
training captures and independently frozen 7.0.0-34 hold-out captures support this
narrow coverage. Other configurations can remain unknown. Windows and macOS are
expressible families without bundled signatures. Cross-family accuracy,
confidence calibration, and performance remain unmeasured. See the
[provenance](../crates/packetcraftr/data/os-fingerprints.provenance.yaml) and
[evaluation](roadmap/evidence/m10/README.md).

`--corpus PATH` loads a `packetcraftr.os-fingerprints/v1` JSON document before
provider activity. It names the exact probe-set version and contains at most 512
signatures, each with at most 64 stable predicates. Unknown fields/versions,
duplicates, incompatible fields, insufficient prerequisites, and documents over
512 KiB fail validation. Every required TCP probe needs exact flags and another
stable predicate. Operator data requires the operator's source/license review.

```rust,no_run
use packetcraftr::{Client, os, target::Target};
# fn example<P: packetcraftr::PacketProviders + packetcraftr::TargetProviders>(client: &Client<P>) -> Result<(), os::Error> {
let request = os::Request::new(
    Target::Address("192.0.2.2".parse().unwrap()), 443, 43125,
    os::builtin_corpus()?,
);
let collector = os::Collector::default();
let report = client.identify_os(request, collector.clone())?;
let aggregate = collector.finish(report)?;
println!("{:?}", aggregate.report.identification.outcome);
# Ok(())
# }
```

Pure parsing/extraction/matching live in
`packetcraftr_core::document::os_fingerprints`; the live crate owns bounded I/O.
The [document schema](../schemas/packetcraftr.os-fingerprints.v1.schema.json),
[example](../examples/documents/os-fingerprints.json), and
[v14 contract](consumer-compatibility.md#output-family-v14) ship together.
M10 remains [In progress](roadmap/m10-os-identification.md) until broader corpus
and native acceptance gates close. Scan integration and release-version claims
are deferred.
