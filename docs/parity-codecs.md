# Practical codec and filter additions

All additions are available from the runtime-neutral `packetcraftr-core` crate.
The CLI's existing `build`, packet-document, `protocols`, display-filter and
`--decode-as` interfaces use the same registry.

## Display filters

```text
raw.bytes matches "^GET /[a-z]+ HTTP/1[.]1$"
len(raw.bytes) > 64
count(ipv4.source) == 2
starts_with(lower(raw.bytes), "get ")
ends_with(raw.bytes, "HTTP/1.1")
ipv4.source != ipv4.destination
any udp.destination_port == 53
all udp.destination_port != 53
```

`len` measures bytes (UTF-8 byte length for text). `count` counts selected scalar
values, including list elements. `lower` and `upper` change ASCII letters only.
`starts_with` and `ends_with` accept function-call or infix syntax. Unmodified
comparisons keep their existing existential semantics. `any` requires at least
one matching operand pair; `all` requires every selected pair to match. Either
missing operand makes the comparison false, including `all`. Requirements such
as stream indexing and timestamp availability include both operands and all
function arguments.

`matches` compiles a Rust byte regex once when the filter is compiled. Text is
matched as UTF-8 bytes; arbitrary byte values are supported by disabling Unicode
mode. Each pattern has an 8 KiB source ceiling. The 1 MiB compiled-regex ceiling
is charged cumulatively as each pattern is compiled, using the engine’s reported
compiled storage plus its Regex handle. The first pattern that would exceed the
shared allowance is rejected. Individual optional compiled engines and DFA caches
each receive a 256 KiB ceiling. A
backslash in filter quoted text must itself be escaped, e.g. `"\\d+"`.

## Registered codecs

| Name | Rust model | Automatic recognition | Bounds and fidelity |
| --- | --- | --- | --- |
| `lldp` | `protocol::link::Lldp`, `LldpTlv` | EtherType `0x88cc` | Three mandatory TLVs, common and unknown values; 256 TLVs; exact padding |
| `stp` (`rstp`) | `protocol::link::Stp` | LLC DSAP/SSAP `0x42`, UI control | Configuration, TCN, RSTP; timer values retain 1/256-second units |
| `tftp` | `protocol::application::tftp::Tftp` | UDP port 69 | RRQ, WRQ, DATA, ACK, ERROR, OACK; ordered option bytes |
| `rtp` | `protocol::application::rtp::Rtp` | Explicit UDP decode-as | v2 header, 15 CSRCs, word-aligned extensions, exact payload and padding |
| `rtcp` | `protocol::application::rtcp::Rtcp` | Explicit UDP decode-as | 64 compound packets; typed SR/RR/SDES/BYE access; exact unknown types |
| `mqtt` | `protocol::application::mqtt::Mqtt` | TCP port 1883 | MQTT 3.1.1 types 1–14, four-byte bounded remaining length; 1 MiB packets |
| `http` (`http1`) | `protocol::application::http::Http` | TCP ports 80/8080 | Typed construction with ordered headers and a 16 MiB body ceiling |

Use an explicit UDP decode-as binding for TFTP transfer ports. Strict CLI construction also accepts these bindings, for example `build --decode-as udp.port=5004:rtp --packet 'ipv4()/udp(destination_port=5004)/rtp()'`. RTP and RTCP use
explicit binding because ports and payload bytes alone do not identify them
reliably. In Rust, `builtin::registry_with` and `builder.bind("udp", port,
"rtp", priority)` add equivalent bindings. MQTT performs packet-level decoding:
an incomplete TCP segment remains exact `raw` bytes and is suitable for separate
stream assembly. Its `fields()` exposes publication metadata and client IDs;
`connect`, `publish`, `acknowledgement`, and `subscribe` construct common controls.
Other controls use the type, flag nibble and exact body fields.

RTCP `Packet::sender_report`, `receiver_report`, `source_description`, and `bye`
construct common packet types. `Packet::contents()` provides their typed values.
The reflection schema exposes the ordered compound packets and their exact body
bytes, making unknown types available for construction, documents and filters.

`Http::new(StartLine, Vec<Header>, Bytes, Framing)` constructs HTTP/1 requests and
responses. `Framing::ContentLength` derives the exact body length;
`Framing::Chunked` supplies complete chunk framing. Existing framing headers are
replaced, all other header ordering is retained, and header injection and
body-forbidden status codes are rejected. The generic construction interface
accepts `method`, `target`, `version`, `status`, `reason`, `headers`, `body`, and
`chunked`. Dissection keeps HTTP headers and following bytes in separate layers,
retaining the existing stream-analysis behavior. Packet documents remain at v2.
See `examples/documents/packet-parity-*.json` for document construction.

Wire checks follow [RTP/RTCP RFC 3550](https://www.rfc-editor.org/info/rfc3550/),
[TFTP RFC 1350](https://www.rfc-editor.org/info/rfc1350/),
[TFTP options RFC 2347](https://www.rfc-editor.org/info/rfc2347/),
[MQTT 3.1.1](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html),
and [HTTP/1.1 RFC 9112](https://www.rfc-editor.org/rfc/rfc9112.html).
LLDP follows [IEEE 802.1AB](https://www.ieee802.org/1/pages/802.1ab.html), with the
mandatory identity and TTL semantics described in the
[IEEE LLDP TLV discussion](https://www.ieee802.org/1/files/public/docs2025/new-bottorff-lldp-tlvs-for-lsvr-0425-v00.pdf).
BPDU fields follow the
[IEEE merged BPDU encoding draft](https://grouper.ieee.org/groups/802/1/files/public/docs2009/aq-seaman-merged-bpdu-encoding-0509.pdf).
