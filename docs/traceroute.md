# Structured traceroute workflow

`traceroute` is a bounded active workflow built from the shared target
resolver, traffic policy, route planner, exact builder, capture-ready exchange,
dissector, and response correlation APIs. It supports UDP, ICMP echo, and TCP
SYN strategies over IPv4 and IPv6 and preserves every attempt at every emitted
hop.

Only trace systems and networks where you have explicit authorization. A
hostname is authorized before DNS, then every distinct answer is authorized
before family selection, probe construction, route lookup, capture, neighbor
discovery, or transmission. Re-running the operation repeats both checks, so a
changed answer cannot inherit earlier approval. Public destinations and
hostname resolution remain independent opt-ins. Interface syntax is validated
early, but system interface lookup is deferred until after target and complete
operation authorization.

```console
# Conventional UDP trace with three attempts per hop.
packetcraftr --output json traceroute 192.168.56.10 \
  --strategy udp --max-hops 20 --attempts 3 \
  --timeout-ms 750 --rate 12

# Portless IPv6 ICMP echo trace.
packetcraftr --output ndjson traceroute fd00::20 \
  --strategy icmp --family ipv6 --max-hops 30

# A TCP SYN trace to a fixed application port.
packetcraftr traceroute lab.example --strategy tcp --port 443 \
  --allow-hostname-resolution
```

UDP uses a unique destination port for each ordered probe, starting at
`--port` (33434 by default). TCP uses a fixed destination port (80 by default)
and a unique sequence. ICMP uses a unique echo identity and rejects `--port`.
Every generated IPv4 TTL or IPv6 hop limit is explicit. `--first-hop`,
`--max-hops`, `--attempts`, `--timeout-ms`, `--rate`, `--max-probes`, and
`--max-duration-ms` are finite and validated before live work. The conservative
complete wire-byte total must fit `--max-packets` and `--max-bytes` before the
first probe is constructed.

One homogeneous hop is one `Client::exchange` batch. Its capture session is
armed and ready before any attempt is transmitted, and shutdown is attempted
on every success or failure path. Hop batches are deliberate bursts; a rate
ceiling delays the next hop by the preceding attempt count divided by the
selected rate. A trace stops after finishing the current hop when any attempt
proves `destination_reached` or a terminal `unreachable` result.

## Correlation and evidence

Every attempt reports its logical sequence, hop limit, strategy, actual
destination port when applicable, send timestamp, response/timeout status,
responder, receive timestamp, latency, reason, and an exact retained frame when
the evidence budget permits it.

| Response kind | Accepted correlated fact |
| --- | --- |
| `intermediate` | ICMPv4 or ICMPv6 time-exceeded response quoting the exact probe |
| `destination_reached` | Matching ICMP echo reply, reverse-tuple UDP response, TCP SYN/ACK or RST, or a UDP port-unreachable response from the destination |
| `unreachable` | Other correlated destination, policy, or administrative ICMP failure |
| timeout status | No checksum-valid, protocol-consistent response before the hop deadline |

Direct replies must pass the registered reverse response matcher. ICMP errors
must quote the original address family, endpoints, protocol, ports and TCP
sequence, or ICMP identity. Checksum diagnostics, unrelated/malformed quotes,
and frames timestamped before the corresponding send cannot advance or
terminate the trace.

Undecodable frames cannot safely be assigned to one attempt. They remain exact,
bounded, hop-scoped evidence under `--max-undecoded`,
`--max-queue-frames`, and `--max-captured-bytes`. Policy denials, unsupported
native capabilities, cancellation/timer failure, and runtime I/O failure use
the normal typed error envelope rather than being reported as network hops.

Text, aggregate JSON, and NDJSON render the same typed result. NDJSON emits one
`hop` event containing every attempt, zero or more hop-scoped `undecoded`
events, and a final `complete` event carrying the selected address, completion
reason, diagnostics, and operation statistics.

## Rust API

`TracerouteRequest` and `TracerouteLimits` describe the portable plan.
`traceroute` accepts the shared component-neutral `TracerouteAuthorizer` and
`TracerouteClock` seams plus an injectable `TracerouteExecutor`. The root
façade supplies `TrafficPolicyTracerouteAuthorizer` and
`ClientTracerouteExecutor`. `classify_traceroute_response` is pure, so IPv4 and
IPv6 intermediate, terminal, unrelated, malformed, and checksum-failure cases
can be tested without network access.
