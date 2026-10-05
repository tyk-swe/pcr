# M13: SCTP and IP-protocol inventory

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M5][m5], [M6][m6] | Inventory beyond TCP and UDP |

PacketcraftR scans TCP and UDP ports and sends ICMP echo. It has an SCTP codec
and a matcher helper that reads an initiate tag, and neither is a scanner: no
scan transport sends SCTP, chunks are carried as opaque bytes, and nothing asks
which IP protocols a host answers at all. Host discovery in [M5][m5] likewise
stops at the mainstream probes.

This milestone adds SCTP scanning, a typed IP-protocol inventory, and the
remaining discovery probe families.

## Outcome

- SCTP INIT and COOKIE-ECHO scans report typed outcomes for SCTP ports.
- The SCTP chunks those scans need are bounded, typed models.
- A bounded set of IP protocol numbers can be inventoried per host, kept
  distinct from transport ports.
- Additional discovery probes can be selected explicitly.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| SCTP | A [codec][sctp-codec] for the common header and checksum and a [matcher helper][sctp-matcher] that reads an initiate tag from opaque chunk bytes; [scan transports][scan-args] are TCP, UDP, and ICMP | SCTP INIT and COOKIE-ECHO scans ([scan techniques][nmap-techniques]) |
| IP protocols | [Requests][scan-request] target TCP/UDP ports or ICMP echo; no protocol-number selection | IP protocol scan ([scan techniques][nmap-techniques]) |
| Discovery probes | SYN, UDP, and echo; none of ACK, ICMP timestamp/netmask, SCTP, or IP-protocol | Those additional probe families ([host discovery][nmap-discovery]) |

## Invariants

- A protocol number is not a transport port. Selections and results for each
  stay separately typed.
- The presence of a codec is not scanner support.
- Ambiguous states remain ambiguous.
- No probe is sent that the request did not select.

## Scope

### M13.1 SCTP INIT and COOKIE-ECHO scans

- SCTP INIT and COOKIE-ECHO scan modes, reusing the core SCTP header, checksum,
  and matcher building blocks.
- Workflow evidence for each attempt, and inference in the [M6][m6-inference]
  vocabulary with SCTP's ambiguous responses kept ambiguous.
- SCTP joins the mixed-protocol plans of [M6][m6-mixed] as a typed protocol.

### M13.2 SCTP chunk models

- Bounded, typed models for the chunks these scans send and must recognize.
- Malformed and truncated chunks decode to diagnostics and evidence, not to a
  port state.

### M13.3 IP-protocol inventory

- A bounded, typed selection of IP protocol numbers per host.
- Correlated positive, negative, and ambiguous evidence for each protocol
  number.

### M13.4 Additional discovery probes

- The relevant discovery probe families that [M5][m5-probes] leaves out: ACK,
  ICMP timestamp and netmask, SCTP, and IP-protocol.
- Each is an explicit discovery strategy with its own correlation, composed by
  the [M5][m5] workflow.

## Change map

| Change | Start here |
| --- | --- |
| Chunk models | core [`protocol/transport/sctp.rs`][sctp-codec] |
| SCTP correlation | core [`protocol/matcher/sctp.rs`][sctp-matcher] |
| Typed protocols and protocol numbers | [`correlation.rs`][correlation], [`scan/request.rs`][scan-request] |
| Probe construction | [`scan/plan/packet.rs`][scan-packets] |
| Inference | [`scan/evidence.rs`][scan-evidence] |
| Raw transmission | netio [`transmit.rs`][netio-transmit], [`platform/transmit/raw_ip.rs`][raw-ip] |
| Arguments and records | [`commands/scan/arguments.rs`][scan-args], [`output/scan.rs`][scan-output] |

## Decisions to settle

1. Which platforms can transmit SCTP and arbitrary IP protocols (recommended:
   record capability per platform and profile before committing a mode; an
   unsupported path publishes a capability failure).
2. Which chunk types get typed models (recommended: only those correlation
   needs, such as INIT, INIT ACK, ABORT, and COOKIE ECHO; the rest stay opaque).
3. Whether IP-protocol inventory has a default selection (recommended: no; the
   selection is explicit and bounded).
4. How a probe is formed for a protocol that needs a valid header to draw a
   reply (recommended: define it per protocol number and record which protocols
   are sent with an empty payload).
5. Which additional discovery probes are relevant (recommended: ACK and ICMP
   timestamp first; the others only with a fixture showing a host they discover
   that [M5][m5-probes] probes miss).

## Exit criteria

- [ ] Each mode has an observable correlation and state matrix covering
      unrelated replies, valid negative replies, malformed chunks, ICMP
      quotations, and silence.
- [ ] Ambiguous states remain ambiguous.
- [ ] Known implementation-dependent counterexamples are acceptance fixtures.
- [ ] Protocol numbers and transport ports are separately typed in requests,
      plans, and output.
- [ ] Additional discovery probes are sent only when explicitly selected.
- [ ] Applicable IPv4, IPv6, Linux, macOS, and Windows native checks pass
      before a mode is marked complete.
- [ ] Unsupported execution paths publish capability failures, not false port,
      protocol, or host classifications.

[m5]: m05-host-discovery.md
[m5-probes]: m05-host-discovery.md#m53-icmp-tcp-and-udp-discovery-probes
[m6]: m06-port-planning-inference.md
[m6-mixed]: m06-port-planning-inference.md#m64-mixed-tcpudp-plans
[m6-inference]: m06-port-planning-inference.md#m65-inferred-states-and-reasons
[correlation]: ../../crates/packetcraftr/src/correlation.rs
[scan-request]: ../../crates/packetcraftr/src/scan/request.rs
[scan-packets]: ../../crates/packetcraftr/src/scan/plan/packet.rs
[scan-evidence]: ../../crates/packetcraftr/src/scan/evidence.rs
[sctp-codec]: ../../crates/packetcraftr-core/src/protocol/transport/sctp.rs
[sctp-matcher]: ../../crates/packetcraftr-core/src/protocol/matcher/sctp.rs
[netio-transmit]: ../../crates/packetcraftr-netio/src/transmit.rs
[raw-ip]: ../../crates/packetcraftr-netio/src/platform/transmit/raw_ip.rs
[scan-args]: ../../crates/packetcraftr-cli/src/commands/scan/arguments.rs
[scan-output]: ../../crates/packetcraftr-cli/src/output/scan.rs
[nmap-techniques]: https://nmap.org/book/man-port-scanning-techniques.html
[nmap-discovery]: https://nmap.org/book/man-host-discovery.html
