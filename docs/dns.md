# Structured DNS workflow

`dns` is a bounded active workflow built from the shared target resolver,
traffic policy, route planner, exact builder, capture-ready exchange,
dissector, and UDP response matcher. The live command sends one standard DNS
query per attempt over IPv4 or IPv6 UDP. DNS messages remain tool-owned raw
payloads; port 53 never enables implicit DNS dissection in the protocol
registry.

Only query servers where you have authorization. The complete attempt and
conservative wire-byte budget is approved before resolution or packet
construction. For a server hostname, every attempt independently authorizes
the declared name before its resolver call and then authorizes every returned
address before family selection or probe construction. A mixed private/public
answer therefore fails closed, and a retry cannot reuse approval for a DNS
rebinding result. Interface syntax is checked early, while system interface,
route, neighbor, capture, and transmission work remains deferred until all
applicable policy checks succeed.

```console
# Query a private recursive server and retain aggregate structured evidence.
packetcraftr --output json dns 192.168.56.53 www.example.test \
  --type a --attempts 2 --timeout-ms 750

# Query an IPv6 server and stream attempts, accepted records, and completion.
packetcraftr --output ndjson dns fd00::53 _service._tcp.example.test \
  --type srv --family ipv6

# A server hostname requires a separate resolver-policy acknowledgement.
packetcraftr dns resolver.lab txt.example.test --type txt \
  --allow-hostname-resolution
```

The supported question types are `a`, `aaaa`, `cname`, `mx`, `ns`, `ptr`,
`soa`, `srv`, `txt`, and `any`. `--attempts`, `--timeout-ms`, `--rate`,
`--max-duration-ms`, message/record/name/TXT bounds, capture queue bounds, and
exact-evidence bounds are finite and validated before live work. `--port`
defaults to 53; `--transaction-id` can make a fixture reproducible, otherwise
the CLI generates a process-local 16-bit value. `--source-port` likewise fixes
the first attempt's port for a fixture; otherwise the CLI independently selects
an ephemeral-range port and advances it for retries. `--no-recursion` clears
the recursion-desired flag.

Each attempt uses `Client::exchange`, so capture reaches its readiness barrier
before transmission and shutdown is attempted on success and every failure
path. The selected interface, preferred source, and `auto`/`layer2`/`layer3`
intent are explicit workflow options. No socket or legacy asynchronous DNS
runtime is hidden inside the portable workflow.

## Validation, relevance, and evidence

A direct response must have a checksum-valid reverse IPv4/IPv6 and UDP tuple
for the exact server address and ports. The DNS transaction ID, response bit,
standard-query opcode, reserved header bit, single IN-class question, owner,
and question type must match. Compression pointers, names, section counts,
RDATA, TXT strings, total records, message bytes, and exact trailing length are
bounded. The pure DNS-over-TCP frame decoder applies the same message checks to
one exact length-prefixed frame, but the current live CLI intentionally exposes
only the capture-ready UDP transport rather than pretending that raw TCP is a
connected DNS session.

An accepted response can have any standard response code, including
`name_error` or `refused`; the numeric and named code remains structured. A
truncation flag is a terminal `truncated` outcome, and no possibly partial
section record is presented as accepted data. Other terminal/fallback outcomes
distinguish `timeout`, `unrelated`, `decode_failure`, and correlated
`network_failure` evidence.

Accepted records are deliberately narrower than the bytes declared by the
server:

- Answers must match the validated question owner/type or a validated CNAME
  chain.
- Authority data must be an IN-class SOA or NS record for the same owner or an
  ancestor of the validated question chain.
- Additional data must be IN-class A/AAAA glue whose owner is referenced by an
  accepted CNAME, MX, NS, or SRV record.

Everything else contributes to `rejected_record_count` and a bounded rejected
record audit trail; it is never merged into accepted answers. Unknown accepted
types retain exact RDATA hexadecimal. TXT character strings retain exact
`strings_hex` alongside their display projection. Text output passes through
the common terminal-control and bidirectional-control escaping boundary, while
JSON uses normal JSON escaping and preserves the exact structured hex value.

Text, aggregate JSON, and NDJSON are renderings of the same typed result.
NDJSON emits attempt, accepted-record, rejected-record, and undecoded events,
then one complete event carrying the final outcome, response metadata,
diagnostics, and operation statistics.

## Rust API

`DnsRequest`, `DnsLimits`, and `DnsResult` describe the portable workflow.
`dns` accepts injectable `DnsExecutor`, shared `DnsAuthorizer`, and shared
`DnsClock` seams. The root façade supplies `TrafficPolicyDnsAuthorizer` over
`TrafficPolicy` plus `HostnameResolver`, and `ClientDnsExecutor` over
`Client::exchange`. `encode_dns_query`, `decode_dns_response`,
`decode_dns_tcp_frame`, and `classify_dns_response` are pure, so valid,
unrelated, malformed, truncated, rebinding, mixed-answer, timeout, and
terminal-text cases can be tested without network access.
