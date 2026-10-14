# OS identification

`identify-os` collects a finite, original TCP/ICMP fingerprint from one numeric
IPv4 or IPv6 target. Supply a known open TCP port and a distinct known closed
TCP port; the workflow verifies both before sending remaining probes.

```sh
packetcraftr --output json identify-os 192.0.2.2 \
  --open-port 443 --closed-port 43125 --interface eth0 --link-mode layer2
packetcraftr --output ndjson identify-os 2001:db8::2 \
  --open-port 443 --closed-port 43125 --attempts 1 --timeout-ms 500
```

## Observations and candidates

Output/v14 (retained in v15) preserves sent packets, retained response frames,
probe/attempt identities, timing, omissions, and diagnostics. Observations record
TCP flags, window, ordered options, MSS, scale, SACK, and timestamp echo; TTL is
retained as observed, never converted into a guessed initial TTL or OS label.

Suitable SYN/ACK replies to both open-port SYN forms and a correlated RST/ACK
from the closed port are required; ICMP echo is optional.

| Outcome | Meaning |
| --- | --- |
| `matched` | Fully satisfied signatures qualify one family. |
| `ambiguous` | Fully satisfied signatures qualify competing families. |
| `unknown` | Suitable required evidence matches no signature. |
| `inconclusive` | Required evidence is missing, unsuitable, contradictory, or retention is incomplete. |

Candidates cite signature, corpus/version, reference, and zero-based supporting
observation indices, ranked by predicate count then signature ID. `qualified` is
ordinal, not a probability, authenticated identity, or release version.

## Probe set and bounds

`packetcraftr.os-probes/v1` defines four authored packets:

| Probe | Authored packet |
| --- | --- |
| `open_syn` | SYN, window 65535, MSS 1460, SACK-permitted, NOP, scale 7; explicit zero alignment. |
| `closed_syn` | SYN to the closed port, window 65535, no options. |
| `timestamp_syn` | Open SYN options plus an operation-specific timestamp. |
| `echo` | ICMP echo with operation-specific correlation bytes. |

Selected SYN/ACK replies receive bounded RST/ACK cleanup. Defaults: 2 attempts
(ceiling 3), 1 s window, 10 pps, 30 s deadline, and 32 transmissions (including
one neighbor request and cleanup), with up to 256 retained frames (1 MiB, 4096 B
snaplen).

## Corpus and library

Bundled `project-os-fingerprints` 1.0.0 contains two qualified Linux signatures
for 1500-byte Ethernet IPv4/IPv6 profiles; see
[provenance](../crates/packetcraftr/data/os-fingerprints.provenance.yaml). `--corpus PATH` validates a
`packetcraftr.os-fingerprints/v1` JSON document (≤ 512 KiB, ≤ 512 signatures,
≤ 64 predicates/signature) before provider activity.

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

Pure parsing/matching lives in `packetcraftr_core::document::os_fingerprints`;
see the [schema](../schemas/packetcraftr.os-fingerprints.v1.schema.json),
[example](../examples/documents/os-fingerprints.json), and
[v14 contract](consumer-compatibility.md#output-family-v14).
