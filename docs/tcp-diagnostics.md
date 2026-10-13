# TCP diagnostic scans

Raw scans can send ACK, window, FIN, NULL, Xmas, Maimon, or custom-flag TCP
segments instead of SYN. Their states are stack-dependent inferences kept beside
every attempt, not reliable open/closed detection, service identification, or
authenticated identity. See [evidence tables](scanner-evidence.md#port-inference)
and [M12](roadmap/m12-tcp-diagnostic-scans.md).

## Use

```sh
packetcraftr scan 192.0.2.10 --tcp-scan ack --ports 22,80,443
packetcraftr scan 192.0.2.10 --tcp-scan window --ports 80
packetcraftr --output ndjson scan 192.0.2.10 --tcp-scan xmas --ports 1-1024 --max-in-flight 32
packetcraftr scan 192.0.2.10 --tcp-scan custom --tcp-flags 0x029 --ports 80
packetcraftr --output json scan 192.0.2.10 --tcp-scan fin --ports 80 --list
```

`--tcp-scan` accepts `syn` (default), `ack`, `window`, `fin`, `null`, `xmas`,
`maimon`, or `custom`. `--tcp-flags` (`0..=0x1ff`) is required for `custom` and
rejected otherwise.

| Mode | Flags | Probe acknowledgment |
| --- | --- | --- |
| `syn` | `0x002` | 0 |
| `ack`, `window` | `0x010` | `sequence + 0x50435201` |
| `fin` | `0x001` | 0 |
| `null` | `0x000` | 0 |
| `xmas` | `0x029` (FIN, PSH, URG) | 0 |
| `maimon` | `0x011` (FIN, ACK) | `sequence + 0x50435201` |
| `custom` | given bits | `sequence + 0x50435201` only if ACK is set |

The nonzero ACK identity binds bare resets to a single probe attempt. Final wire
checks require exact flags, acknowledgment, endpoint, address, sequence, and no
payload or options.

## Scope and inference

- Applies to raw scan-stage TCP endpoints only; discovery TCP stays SYN, and
  connect, UDP, ICMP, and traceroute probes are unaffected. Non-SYN modes
  require the raw method and at least one TCP scan endpoint.
- Rules are `tcp_<mode>.<reason>` ([rank and attempt rules](scanner-evidence.md#port-inference)):

| Mode | Reset | ICMP unreachable | Time exceeded / other | Silence |
| --- | --- | --- | --- | --- |
| ACK | `unfiltered` | `filtered` | `unknown` | `filtered` |
| Window | window >0 `open`; 0 `closed`; missing `unknown` | `filtered` | `unknown` | `filtered` |
| FIN, NULL, Xmas, Maimon | `closed` | `filtered` | `unknown` | `open_or_filtered` |
| Custom | `unknown` (`tcp_custom.reply`) | `unknown` | `unknown` | `unknown` |

`unfiltered` means a reset reached the scanner, never that a service listens.
Custom segments are observation-only and never adopt another mode's rules.

## Library and output

```text
request.tcp_scan = packetcraftr::scan::TcpScan::Ack;
let report = client.scan(request, sink)?;
```

`scan::TcpScan` defaults to `Syn` and exposes `as_str`, `flags`, and `validate`.
Output/v15 publishes `tcp_scan` (`{mode, flags}`) and `tcp_window`; see the
[v15 contract](consumer-compatibility.md#output-family-v15),
[aggregate fixture](../examples/documents/output-scan-tcp-diagnostic.json),
[event fixture](../examples/documents/output-scan-tcp-diagnostic-event.json),
and [native validation](native-validation.md#m12-tcp-diagnostic-acceptance).
