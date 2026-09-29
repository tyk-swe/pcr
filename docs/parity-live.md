# Live parity features

Replay accepts the same fixed outer MAC, IP address, TCP/UDP port, and VLAN edits
as offline rewriting. Rust callers use `replay::Request::with_rewrite` with a
`packetcraftr_core::transform::HeaderRewrite`. Selection evaluates the original
capture. Pacing, byte limits, route lookup, destination policy, source ownership,
and final MTU checks use the transformed frame. Rewriting malformed or truncated
packets fails before transmission; timestamps and capture identities are retained.

Capture accepts `--direction both|in|out`. Direction is applied before readiness
and appears in requested/applied/effective capture settings. Unsupported controls
fail explicitly. The libpcap backend supports all three directions; Npcap reports
an explicit unsupported setting for ingress/egress selection. Rust callers set
`capture::NativeSettings::direction`. Repeat `--capture-filter-for NAME_OR_INDEX=BPF`
to replace the global BPF for a selected source. Rust callers provide native
interface IDs and filters in `capture::GroupRequest::filters`. Every source's
filter validates before the first source activates, duplicate overrides fail,
and unselected sources cannot receive overrides.

Scan accepts `--shuffle-seed U64`. A stable operation-local Fisher–Yates schedule
with SplitMix64 output shuffles address, destination-port, and attempt triples.
Raw and connect scans use the same schedule. No seed preserves the raw scan's
existing address/attempt/port order. Generated sequence identities follow the
scheduled order; retries and concurrent windows retain the operation-wide rate,
deadline, and evidence budgets.

Raw TCP scans accept `--tcp-mode syn|ack|fin|null|xmas`. SYN remains the default.
ACK resets classify the endpoint as `unfiltered`; silence for ACK is `filtered`.
FIN, NULL, and Xmas resets classify it as `closed`; silence is `open_or_filtered`.
These outcomes report the observed scan behavior without claiming service identity.
The Rust API exposes `scan::TcpMode` and the corresponding classification variants.
The scan flags and silence/reset interpretations follow the documented
[Nmap techniques](https://nmap.org/book/man-port-scanning-techniques.html).

`scan --connect --tcp-profiles PATH` loads `packetcraftr.tcp-profiles/v1` documents.
Each assignment maps nonempty ports to a named profile with exact hexadecimal
request bytes and either `any` or bounded offset/mask response checks. Documents
and compiled profiles are capped at 1 MiB; responses default to 4 KiB and cannot
exceed 64 KiB. Requests cannot exceed 64 KiB. For example:

```json
{
  "schema": "packetcraftr.tcp-profiles/v1",
  "profiles": [{
    "ports": [8080],
    "profile": {
      "name": "HTTP status",
      "request": {"type": "bytes", "data": "48454144202f20485454502f312e300d0a0d0a"},
      "response": {
        "type": "bytes", "min_length": 5, "max_length": 4096,
        "checks": [{"offset": 0, "data": "485454502f"}]
      }
    }
  }]
}
```

Rust callers parse with `document::tcp_profiles::parse`, compile with
`scan::profile::compile_tcp`, assign `scan::Request::tcp_profiles`, and call
`Client::scan_connect`. The complete planned request/response traffic is authorized
before connection. The connected peer is checked before every read and write.
Banner evidence retains exact response bytes, partial request-write counts,
response-check status, and partial I/O errors, independently of successful TCP
connection evidence. Profiles are rejected by the raw scanner.

Traceroute accepts `--udp-port-mode increment|fixed`. Increment remains the default.
Fixed mode keeps source/destination ports and IPv6 flow label constant. A unique
UDP payload word produces a unique checksum token for every probe, and correlation
requires that exact token in a valid ICMP quote. Direct UDP replies that cannot
identify a probe receive no credit. Fixed mode admits at most 65,535 probes per
operation. Rust callers use `traceroute::UdpPortMode`.

`--cycles N` repeats a trace with a shared authorization, deadline, and cumulative
probe/evidence budget. The default is one cycle; the maximum is 1,024. The default
`--cycle-interval-ms` is 1,000. Each cycle retains one-based cycle numbers and stops
at its own destination/unreachable evidence. Hop aggregates retain responder
counts and latency count/min/mean/max, with loss over every cycle's attempted
probes. Rust callers set `Request::cycles` and `Request::cycle_interval`.

Correlated IPv4 fragmentation-needed and IPv6 Packet Too Big responses retain
`advertised_mtu` in scan/traceroute evidence. Unknown IPv4 MTU zero is preserved.
Unrelated quotes and checksum-invalid responses never receive MTU credit.

These additions use `packetcraftr.output/v7`. Packet documents remain v2.
