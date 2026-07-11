# Structured scan workflow

`scan` is a bounded active workflow built from the same target resolver,
traffic policy, packet templates, route planner, exact builder, capture-ready
exchange, dissector, and response matchers as the lower-level Rust API. It
supports TCP SYN, UDP, and ICMP echo probes over IPv4 and IPv6.

Only scan systems and networks where you have explicit authorization. Public
addresses and hostname resolution are separate opt-ins. A hostname is checked
before DNS; every distinct DNS answer is checked before address-family
selection, packet construction, route lookup, capture, neighbor discovery, or
transmission. Re-running a scan repeats both checks, so a changed DNS answer
cannot inherit an earlier authorization. An optional interface name/index is
validated syntactically up front but resolved against the system only after
target authorization succeeds.

```console
# TCP SYN scan of two private-lab ports.
packetcraftr --output json scan 192.168.56.10 \
  --transport tcp --ports 22,443 --attempts 2 \
  --timeout-ms 750 --batch-size 2 --rate 20 \
  --max-packets 4 --max-bytes 4096

# Portless IPv6 ICMP echo scan.
packetcraftr --output ndjson scan fd00::20 \
  --transport icmp --family ipv6 --timeout-ms 1000

# DNS and public traffic require independent acknowledgements.
packetcraftr --output json scan lab.example --transport udp --ports 53 \
  --allow-hostname-resolution --allow-public-destinations
```

TCP and UDP require one or more `--ports`; ICMP rejects ports. In the v1 output
contract, a portless ICMP endpoint uses `port: 0` while its evidence omits
`destination_port` and identifies `icmpv4` or `icmpv6`. Duplicate ports
are removed without changing their first-seen order. `--attempts`,
`--max-ports`, `--max-probes`, `--batch-size`, `--timeout-ms`, `--rate`, and
`--max-duration-ms` are validated before live work. Packet and conservative
wire-byte totals must also fit `--max-packets` and `--max-bytes` before the
first route or send. A rate-limited batch is an explicit burst; the next batch
is delayed by the preceding batch size divided by the selected probe rate.

Each homogeneous batch uses `Client::exchange`. Capture is armed and its
readiness barrier is crossed before the first probe, and shutdown is attempted
on every success or failure path. Response, unsolicited ICMP, and undecodable
traffic share the configured capture queue. Exact response and undecodable
frames are additionally bounded across the complete scan by
`--max-queue-frames`, `--max-captured-bytes`, and `--max-undecoded`.

## Classifications and evidence

Every address/transport/port endpoint has one evidence record per attempt.
Evidence reports `response` or `timeout`, its own classification, timestamps,
responder, latency, reason, and an exact frame when the operation-wide evidence
budget permits it. Aggregate classification uses the strongest correlated
fact observed across attempts.

| Classification | Correlated fact |
| --- | --- |
| `open` | TCP SYN/ACK, reverse-tuple UDP response, or matching ICMP echo reply |
| `closed` | TCP RST or UDP ICMP port-unreachable response |
| `filtered` | Correlated administrative/policy rejection or time-exceeded response |
| `unreachable` | Other correlated ICMP destination-unreachable response |
| `unknown` | A protocol-consistent direct response with inconclusive semantics |
| `timeout` | No checksum-valid, protocol-consistent response before the deadline |

Direct TCP/UDP and echo responses must pass the registered response matcher.
ICMP errors must quote the exact original address family, endpoints, protocol,
and transport tuple or echo identifier. A response with a checksum diagnostic,
a pre-send timestamp, or an inconsistent quote cannot affect classification.
Unparseable captured frames remain bounded exact evidence rather than being
silently treated as a response.

Policy denial and runtime failure are not endpoint classifications. They use
the normal structured error envelope and stable exit classes, so automation
can distinguish them from timeouts and network responses.

Text, aggregate JSON, and NDJSON are renderings of the same typed scan result.
NDJSON emits `port` and `undecoded` events followed by one `complete` event
carrying final diagnostics and operation statistics.

## Rust API

`ScanRequest` and `ScanLimits` describe the portable operation. `scan` accepts
injectable component-neutral `ScanAuthorizer`, `ScanExecutor`, and `ScanClock`
seams. The root façade supplies `TrafficPolicyScanAuthorizer` over
`TrafficPolicy` plus `HostnameResolver`, and `ClientScanExecutor` over
`Client::exchange`. `classify_scan_response` is a pure matcher/classifier
suitable for tests and custom workflows. No network access is required to test
planning, timing, classification, or authorization order.
