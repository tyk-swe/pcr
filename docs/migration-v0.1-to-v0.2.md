# Migrating from PacketcraftR v0.1 to v0.2

v0.2 intentionally replaces the v0.1 packet pipeline and CLI. There is no compatibility adapter for old flags, rule files, or JSON output. Existing valid PCAP files remain supported.

This guide documents the target v0.2 interface. During alpha development, `packetcraftr --help` is authoritative: the final command names are present, but commands not yet implemented return exit code 4 with an explicit capability error.

## The central change

v0.1 combined packet fields and workflow behavior in one command. v0.2 separates them:

```text
Packet or PacketTemplate       Workflow options
------------------------       ----------------
ordered protocol layers        plan / build / send / exchange
wire fields                    route and interface preferences
payload bytes                  timeouts and retry policy
Auto / Exact / Raw intent      capture and replay behavior
                               output format and traffic policy
```

A reusable packet never contains an interface name, listener configuration, output settings, retry policy, or logging destination.

## Command mapping

The expressions below show the intended shape. Field spellings can still change before the beta freeze.

| v0.1 | v0.2 replacement |
| --- | --- |
| `dry-run` or global `--dry-run` | `plan` for passive route/source planning; `build` for bytes without route lookup |
| `send` with many layer flags | `send --packet '<expression>'` or `send --packet-file <document>` |
| one-shot send plus reply listener flags | `exchange` with packet input and separate exchange/capture options |
| `listen` | `capture` for live streaming; `read` for offline capture input |
| `dns-query` | `dns` |
| `scan ...` | `scan ...` returning structured evidence and classifications |
| `traceroute` | `traceroute` returning every probe and response |
| payload-only fuzzing | `fuzz`, offline by default and field-aware |
| packet logging as a send side effect | explicit output, `write_capture`, or a pipeline to PCAP/PCAPNG |
| no equivalent | `dissect`, `read`, `replay`, `interfaces`, and `routes` |
| daemon/rules/external command actions | removed; compose the Rust API or CLI from an application or scheduler |
| interactive REPL | removed; use shell history, packet documents, or a Rust application |
| embedded Prometheus HTTP endpoint | removed; export typed `OperationStats` through the application's observability stack |

### Dry run becomes two explicit operations

Use `build` when only packet bytes and diagnostics are required:

```console
packetcraftr build --packet 'ipv4(dst="192.0.2.10")/udp(dport=9)/raw(text="hello")'
```

Use `plan` when route, interface, selected source, MTU, and link-mode information are required:

```console
packetcraftr plan --packet 'ipv4(dst="192.0.2.10")/udp(dport=9)/raw(text="hello")'
```

`plan` may query passive operating-system state. It must not perform ARP, NDP, capture, or transmission. Unresolved destination MAC addresses remain reported as unresolved.

### Flag-heavy packets become expressions

Representative v0.1 preview:

```console
packetcraftr dry-run -d 192.0.2.10 --data-hex '01 02 03' tcp --dport 443
```

Target v0.2 expression:

```console
packetcraftr build --packet 'ipv4(dst="192.0.2.10")/tcp(dport=443)/raw(hex="010203")'
```

Explicit Ethernet and VLAN intent is represented by actual layers:

```console
packetcraftr plan --packet 'ether(src="02:00:00:00:00:01")/vlan(vid=20)/ipv4(dst="198.51.100.8")/icmp()'
```

That packet cannot silently become a Layer 3 send. Conversely, requesting Layer 3 for a packet containing Ethernet is an error.

### Packet input is exclusive

Exactly one recipe source is accepted:

```console
packetcraftr build --packet 'ipv6(dst="2001:db8::2")/udp(dport=53)'
packetcraftr build --packet-file packet.yaml
packetcraftr build < packet.json
```

Supplying more than one source is a CLI error with exit code 2.

## Packet documents

Complex packets move to versioned JSON or YAML with the identifier `packetcraftr.packet/v1`. The following is an illustrative alpha document; validate it against the [schema shipped with PacketcraftR](../schemas/packetcraftr.packet.v1.schema.json) and see the complete [IPv4/UDP JSON example](../examples/documents/packet-ipv4-udp.json):

```yaml
schema: packetcraftr.packet/v1
layers:
  - protocol: ethernet
    fields:
      source:
        type: mac
        value: [2, 0, 0, 0, 0, 1]
      destination:
        type: mac
        value: [2, 0, 0, 0, 0, 2]
  - protocol: ipv4
    fields:
      source:
        type: ipv4
        value: "192.0.2.1"
      destination:
        type: ipv4
        value: "192.0.2.2"
  - protocol: udp
    fields:
      source_port:
        type: unsigned
        value: 49152
      destination_port:
        type: unsigned
        value: 9
  - protocol: raw
    fields:
      bytes:
        type: bytes
        value: [104, 101, 108, 108, 111]
```

Reflective document values carry an explicit `type`. Derived fields omitted from a fresh typed layer retain their codec defaults, normally `Auto`; serializers include their reflected representation when exact or raw intent must be preserved.

Do not put route, interface, timeout, capture, replay, traffic policy, or output settings in this document. Keep those at the command or client call site.

## Derived fields and malformed packets

Fresh typed layers use automatic values for lengths, checksums, offsets, and protocol discriminators. Decoded packets preserve exact values and original bytes. Calling `normalize()` returns dependent fields to automatic derivation.

- Strict building rejects inconsistent exact values and unbound layers.
- Permissive building can emit requested inconsistencies, but records diagnostics.
- Live transmission of a permissive build requires a separate malformed-transmission opt-in. Choosing permissive build mode alone is insufficient.

The old practice of selecting an EtherType while emitting unrelated IP bytes is rejected. A `Raw` child remains valid behind an unknown discriminator so unsupported captured protocols can round-trip exactly, but strict mode rejects `Raw` behind a discriminator that the registry maps to a typed child. Use the registered layer/codec for known protocols; permissive mode is required to preserve a deliberate known-discriminator mismatch.

`CapturedFrame::new` is now fallible because a Rust byte slice can be larger than the capture record's `u32` length fields. Use `try_with_lengths` when captured and original wire lengths differ; it rejects a byte-count mismatch or an original length smaller than the captured length.

## Output migration

Do not parse v0.1 human output or JSON in v0.2.

| Need | v0.2 format |
| --- | --- |
| Human inspection | text |
| Aggregate automation result | `packetcraftr.output/v1` JSON object/array |
| Capture or event stream | NDJSON |
| Exact printable bytes | whole-frame hex |
| Exact binary bytes | raw |
| Capture interchange | PCAP or PCAPNG |

Display limits affect presentation only. Captured bytes retained by the API and written to capture files remain complete up to the configured snap length.

Exit codes are stable at the v0.2 CLI freeze:

| Code | Meaning |
| ---: | --- |
| 0 | Success |
| 2 | CLI or packet-document/schema error |
| 3 | Packet build or dissection error |
| 4 | Unsupported capability, missing native dependency, or privilege error |
| 5 | Route, capture, send, timeout, or other runtime I/O error |
| 6 | Traffic-policy denial |
| 70 | Internal invariant failure |

## Rust API migration

v0.1 exposed a `run_cli`-oriented façade and private fixed builders. v0.2 applications should:

1. Construct a `RegistryBuilder`, add built-in and application protocol modules, then freeze a `ProtocolRegistry`.
2. Construct an ordered `Packet` or bounded `PacketTemplate`.
3. Use `Builder` and `Dissector` directly for portable/offline work.
4. Use a configured high-level `Client` for route-aware live work.
5. Consume typed results and non-exhaustive typed errors. `anyhow` is confined to CLI composition.

Root `packetcraftr` reexports are the stable application import path even after internal component crates are extracted.

Applications that need native Layer 2 route materialization can compose `SystemRouteProvider`, `SystemNeighborResolver`, and the typed native I/O providers. `RoutePlanner::plan` remains passive; `RoutePlanner::materialize` is the explicit boundary that may perform bounded ARP/NDP. Custom resolvers can continue implementing the legacy `NeighborResolver::resolve` method, while `resolve_request` receives interface-owned MAC/IP, next hop, VLAN, MTU, and link-type context and can return captured evidence.

## Feature migration

The old `experimental`, `daemon`, `repl`, `rules`, `metrics`, and per-tool feature maze has been removed. The root crate has four narrow native capabilities in this checkpoint: default `live` for the temporary Unix interface enumerator, `native-route` for passive target-native route/interface discovery, `native-layer2` for native capture/injection, and `native-layer3` for raw IP transmission. Packet construction, dissection, documents, reassembly, offline capture, neighbor protocol logic, and injected providers remain portable without default features. `native-route` alone does not emit ARP/NDP, capture, or transmission. `native-layer2` explicitly opts into system libpcap on Linux/macOS or runtime-loaded Npcap 1.88 on Windows x86_64 MSVC; `native-layer3` opts into target raw sockets. Selecting all three supplies the complete native planning and send path.

Raw IPv4 socket kernels do not preserve every possible crafted header. In particular, a zero identification or inconsistent total length/checksum can be rewritten. `SystemLayer3Io` fails those cases before the socket call; set a nonzero IPv4 identification and build internally consistent lengths/checksums when using the native Layer 3 path. Windows silently discards spoofed raw UDP on affected client editions, so that case is rejected before send; other raw-socket restrictions remain typed native errors.

If an application previously depended on an embedded subsystem, move orchestration outward:

- Schedule finite CLI invocations with the operating system or an application-owned job runner.
- Implement policy and automation in application code around typed PacketcraftR results.
- Export `OperationStats` through the application's metrics library.
- Build a custom interactive interface on the public Rust API if one is required.

## Rollout advice

Pin an exact alpha version, store packet documents in version control, validate them in CI, and compare exact built bytes before enabling live transmission. Move to beta only after all used APIs and document fields appear in the beta migration notes. Existing v0.1 deployments that need only critical fixes should remain on `release/0.1` until the v0.2 release candidate is qualified.
