# TCP diagnostic scans

Raw scans can send an ACK, window, FIN, NULL, Xmas, Maimon, or custom-flag TCP
segment instead of a SYN. These are diagnostics: their states are
stack-dependent inferences kept beside every attempt, not reliable open/closed
detection, service identification, or authenticated identity. Use them only on
authorized targets, with finite budgets. See the
[evidence tables](scanner-evidence.md#port-inference) and
[M12](roadmap/m12-tcp-diagnostic-scans.md) for acceptance status.

## Use

```sh
packetcraftr scan 192.0.2.10 --tcp-scan ack --ports 22,80,443
packetcraftr scan 192.0.2.10 --tcp-scan window --ports 80
packetcraftr --output ndjson scan 192.0.2.10 --tcp-scan xmas --ports 1-1024 --max-in-flight 32
packetcraftr scan 192.0.2.10 --tcp-scan custom --tcp-flags 0x029 --ports 80
packetcraftr --output json scan 192.0.2.10 --tcp-scan fin --ports 80 --list
```

`--tcp-scan` is `syn` (default), `ack`, `window`, `fin`, `null`, `xmas`, `maimon`,
or `custom`. `--tcp-flags` takes decimal or `0x` hexadecimal bits within
`0..=0x1ff` and is required only for `custom`; it is rejected with any other mode.
Everything is validated before resolution or network I/O.

| Mode | Flags | Probe acknowledgment |
| --- | --- | --- |
| `syn` | `0x002` | 0 |
| `ack`, `window` | `0x010` | `sequence + 0x50435201` |
| `fin` | `0x001` | 0 |
| `null` | `0x000` | 0 |
| `xmas` | `0x029` (FIN, PSH, URG) | 0 |
| `maimon` | `0x011` (FIN, ACK) | `sequence + 0x50435201` |
| `custom` | the given bits | per-sequence only if ACK is set |

The sequence is the operation's probe sequence. The nonzero ACK identity makes a
bare reset (whose sequence equals the probe acknowledgment) bind to one probe, so
retries never share a reset identity. The final wire check requires the exact flags,
acknowledgment, endpoint, address, sequence, and no payload or options.

## Scope and requirements

- The mode applies to scan-stage TCP endpoints. Discovery TCP probes stay SYN, UDP
  and ICMP endpoints are unaffected (TCP and UDP may be mixed), and traceroute and
  connect probes build their own segments. A reset may still show a host responded.
- A non-SYN mode needs the raw method and at least one scan TCP endpoint.
  Discovery-only, UDP-only, and ICMP-only requests are rejected. `--connect`,
  `--method tcp-connect`, and `--list` without TCP ports fail; `--method auto` stays
  raw and reports why. Nothing falls back to a connection.
- Raw privileges, policy, pacing, `--max-probes`, `--max-duration-ms`, preparation,
  packet/byte, and evidence ceilings apply unchanged; failures keep partial evidence.
- `--list` stays packet-free and publishes the effective mode and flags.

## Inference

Rules are `tcp_<mode>.<reason>`; attempts remain authoritative.

| Mode | Reset | ICMP unreachable | Time exceeded / other | Silence |
| --- | --- | --- | --- | --- |
| ACK | `unfiltered` | `filtered` | `unknown` | `filtered` |
| Window | window >0 `open`; 0 `closed`; missing `unknown` | `filtered` | `unknown` | `filtered` |
| FIN, NULL, Xmas, Maimon | `closed` | `filtered` | `unknown` | `open_or_filtered` |
| Custom | `unknown` (`tcp_custom.reply`) | `unknown` | `unknown` | `unknown` |

`unfiltered` means a probe reached a host that reset it, never that a service
listens. Window and FIN-family behavior varies by operating system, firewall, and
middlebox; treat them as hints to corroborate. A SYN/ACK or other unexpected TCP
reply to a diagnostic probe is `unknown`. Silence can be loss. Operational failures
(send, deadline, preparation) never imply a port state.

A custom segment is observation-only: it reports replies and the retained window,
and never infers open or closed. It never adopts another mode's rules, even when
its flags equal that mode's.

## Library

Set the mode on an otherwise ordinary scan request, then run it as any scan:

```text
request.tcp_scan = packetcraftr::scan::TcpScan::Ack;
let report = client.scan(request, sink)?;
```

This is a usage sketch, not a complete program: `request`, `client`, and `sink`
come from your existing scan setup (see the scan examples in the crate).

`scan::TcpScan` is `Copy`, defaults to `Syn`, and exposes `as_str`, `flags`, and
`validate`. Probes and `ProbeEvidence` carry the effective mode; `ProbeEvidence`
also retains `tcp_window`. The serial, pipelined, and adaptive engines share the
same construction, correlation, and inference.

## Output and limits

Output/v15 publishes `tcp_scan` `{mode, flags}` and `tcp_window`; see the
[v15 contract](consumer-compatibility.md#output-family-v15). The example
[aggregate](../examples/documents/output-scan-tcp-diagnostic.json) and
[stream record](../examples/documents/output-scan-tcp-diagnostic-event.json) are
project-authored fixtures, not captured traffic.

Software tests inject independent IPv4 and IPv6 responders. M12 native
cross-platform runs and independent operating-system ground truth are still open,
so no native parity or completed gate is claimed. Idle, bounce, decoy, and
evasion scans are out of scope.

## Independent expectations and native checks

The original scanner corpus (dataset 1.7.0) declares eight response conditions
for all seven diagnostic modes. Its dual-stack workflow matrix covers ordinary,
wrong-identity/checksum, reordered, duplicate, and late delivery through serial,
pipelined, and adaptive engines. The injected responder exercises the workflow;
independent native wire encoding belongs to the separate Linux peer.

The reviewed `tcp_diagnostics` native workflow route runs independently encoded
Linux replies plus known kernel sockets, and hosted macOS/Windows loopback sockets,
across five profiles with JSON/NDJSON and serial/pipelined scans. Retained evidence
separates socket truth, observed response/window, inferred state/rule, and heuristic
divergences. Unsupported or missing execution never establishes parity. See
[native validation](native-validation.md#m12-tcp-diagnostic-acceptance) for exact
revision admission, isolation, limits, and report interpretation. Cross-platform
recordings and broader stack-dependent accuracy remain open M12 gates.
