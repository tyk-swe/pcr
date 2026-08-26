# Packet Document Format (packet/v2)

A packet document specifies a network packet as a list of protocol layers with typed field values. It is serialized in YAML or JSON under the `packetcraftr.packet/v2` schema.

Here is the same packet in YAML and JSON:

```yaml
schema: packetcraftr.packet/v2
layers:
  - ethernet:
      destination: 02:00:00:00:00:02
      source: 02:00:00:00:00:01
  - ipv4:
      identification: 4660
      dont_fragment: true
      source: 192.0.2.1
      destination: 192.0.2.2
  - udp:
      source_port: 49152
      destination_port: 9
  - raw:
      bytes: 0x68656c6c6f
```

```json
{
  "schema": "packetcraftr.packet/v2",
  "layers": [
    {
      "ethernet": {
        "destination": "02:00:00:00:00:02",
        "source": "02:00:00:00:00:01"
      }
    },
    {
      "ipv4": {
        "identification": 4660,
        "dont_fragment": true,
        "source": "192.0.2.1",
        "destination": "192.0.2.2"
      }
    },
    {
      "udp": {
        "source_port": 49152,
        "destination_port": 9
      }
    },
    {
      "raw": {
        "bytes": "0x68656c6c6f"
      }
    }
  ]
}
```

## Layers

Each entry in `layers` is a single-key map where the key is a protocol name and the value is a map of fields.

Input parsers accept protocol aliases (for example, `ip` for `ipv4` or `eth` for `ethernet`). Output formats always emit canonical protocol and field names.

Run `packetcraftr protocols` to list supported protocols (output trimmed with `...`):

```console
$ packetcraftr protocols
ah aliases=[] build=true dissect=true exact_round_trip=true matcher=false decode_only=false
arp aliases=[] build=true dissect=true exact_round_trip=true matcher=false decode_only=false
bsd_loop aliases=[loop] build=true dissect=true exact_round_trip=true matcher=false decode_only=false
...
```

Run `packetcraftr protocols <P> --example` to print a starter layer containing required fields:

```console
$ packetcraftr protocols ipv4 --example
- ipv4: {source: 192.0.2.1, destination: 192.0.2.1}
```

## Field Tiers

Every protocol field belongs to one of three tiers:

- **Required**: Must be present in the document. Omitting a required field causes a `document.missing_required` error.
- **Derived**: Computed automatically across layers during build (for example `ipv4.total_length`, `ipv4.protocol`, `ipv4.checksum`, `ethernet.ether_type`). Omitting a derived field is equivalent to specifying `auto`.
- **Optional**: Has a fixed default in the protocol schema. Omitting an optional field uses that default.

Run `packetcraftr protocols <P>` to inspect field tiers and defaults (output trimmed with `...`):

```console
$ packetcraftr protocols ipv4
protocol: ipv4
aliases: [ip, ip4]
build: true
dissect: true
...
fields:
  dscp_ecn kind=unsigned tier=optional default=0 max=255 aliases=[] required=false derived=false description=DSCP and ECN octet
  total_length kind=unsigned tier=derived default=none max=65535 aliases=[] required=false derived=true description=IPv4 total length
  ttl kind=unsigned tier=optional default=64 max=255 aliases=[] required=false derived=false description=Time to live
  checksum kind=unsigned tier=derived default=none max=65535 aliases=[] required=false derived=true description=IPv4 header checksum
  source kind=ipv4 tier=required default=none max=none aliases=[src] required=true derived=false description=Source IPv4 address
  destination kind=ipv4 tier=required default=none max=none aliases=[dst] required=true derived=false description=Destination IPv4 address
  ...
```

## Value Text Forms

The protocol schema defines the data kind for each field. Field values must match the accepted text forms:

| Kind | Accepted spellings | Example |
| --- | --- | --- |
| `bool` | `true`, `false` (case-insensitive) | `dont_fragment: true` |
| `unsigned` | Decimal digits or `0x`/`0X` hex string (up to field `max`) | `ttl: 64`, `identification: 0x1234` |
| `signed` | Optional `-` followed by decimal digits or `0x`/`0X` hex string | `offset: -10`, `offset: -0x0a` |
| `text` | UTF-8 string | `text: "hello"` |
| `bytes` | `0x`/`0X` followed by an even number of hex digits (`0x` is empty) | `bytes: 0x68656c6c6f`, `options: 0x` |
| `ipv4` | Dotted-quad IPv4 address | `source: 192.0.2.1` |
| `ipv6` | Standard IPv6 address string (zone IDs rejected) | `source: 2001:db8::1` |
| `mac` | Colon or hyphen-separated 6-byte MAC address | `destination: 02:00:00:00:00:02` |
| `list` | Sequence of scalar values matching the element kind | `segments: [2001:db8::1, 2001:db8::2]` |

YAML scalars are parsed as text before kind coercion:
- `010` is read as decimal 10, not octal 8.
- `0x10` is read as decimal 16.
- `1e3` fails with a value form error; scientific notation is not accepted for integers.
- `yes`, `no`, `on`, and `off` are not accepted as booleans.
- Bytes are hex-only (`0x...`); the legacy `{text: ...}` map syntax is not supported in documents.

## Derived Fields

Derived fields support three representations:
1. Omitted or `auto`: Computed during packet construction.
2. Literal value (for example `checksum: 0xdead`): In strict mode (`--mode strict`, default), the builder asserts that the literal matches the computed value; if not, it exits with an error. In permissive mode (`--mode permissive`), the builder emits the literal directly.
3. Raw map `{raw: 0x...}`: Emits explicit bytes directly under permissive mode.

In CLI expressions, raw values use the `raw:0x...` syntax:

```console
$ packetcraftr build --packet 'ipv4(source=192.0.2.1,destination=192.0.2.2,checksum=raw:0xdead)/udp(source_port=49152,destination_port=9)' --mode permissive --output hex
4500001c000000004011deadc0000201c0000202c00000090008bbd0
```

## Emission and Minimization

`dissect --output document` and `read --output document` emit minimized v2 documents.

Minimization tests whether rebuilding the packet with `auto` on derived fields reproduces the original wire bytes:
- If the rebuilt bytes match, derived fields matching `auto` and optional fields matching schema defaults are omitted.
- If the rebuilt bytes differ (for example due to a corrupt checksum) or rebuild fails (due to a truncated frame), derived fields are emitted as full literals.
- Passing `--full` skips minimization and emits all fields.

Decode-only layers (`tls`, `dns`, `raw_ip`) cannot be constructed directly from document layer syntax. Document emission writes them as `raw: {bytes: "0x..."}` so the emitted document can be built.

`dissect --output document` emits a single document:

```console
$ packetcraftr dissect --hex '020000000002020000000001080045000021000000004011f6c8c0000201c0000202c0000009000d77f468656c6c6f' --output document
schema: packetcraftr.packet/v2
layers:
  - ethernet:
      destination: "02:00:00:00:00:02"
      source: "02:00:00:00:00:01"
  - ipv4:
      source: "192.0.2.1"
      destination: "192.0.2.2"
  - udp:
      source_port: 49152
      destination_port: 9
  - raw:
      bytes: "0x68656c6c6f"
```

`read --output document` emits a multi-document YAML stream where frames are separated by `---` (output trimmed with `...`):

```console
$ packetcraftr read examples/captures/tls-handshake.pcapng --max-frames 2 --output document
---
schema: packetcraftr.packet/v2
layers:
  - ipv4:
      source: "192.0.2.1"
      destination: "198.51.100.2"
  - tcp:
      source_port: 54321
      destination_port: 443
      sequence: 1000
      flags: 2
      window: 64240
---
schema: packetcraftr.packet/v2
layers:
  - ipv4:
      source: "198.51.100.2"
      destination: "192.0.2.1"
  - tcp:
      source_port: 443
      destination_port: 54321
      sequence: 5000
      acknowledgment: 1001
      flags: 18
      window: 65535
...
```

## Diagnostic Codes

Document parsing and validation errors use structured `document.*` diagnostic codes:

| Code | Exit | When |
| --- | --- | --- |
| `document.deprecated_schema` | 0 (warning) | v1 document read |
| `document.unknown_schema` | 2 | `schema` key missing or not `packetcraftr.packet/v1` or `packetcraftr.packet/v2` |
| `document.layer_shape` | 2 | a layer map has zero or more than one key |
| `document.unknown_protocol` | 2 | layer key is not a recognized protocol or alias |
| `document.unknown_field` | 2 | field key not in the protocol schema |
| `document.duplicate_field` | 2 | the same field is specified by alias and canonical name in one layer |
| `document.value_form` | 2 | scalar does not parse as the field's kind or value exceeds `max` |
| `document.auto_not_derived` | 2 | `auto` specified on a required or optional field |
| `document.missing_required` | 2 | required field omitted |
| `document.decode_only` | 2 | document contains a decode-only protocol layer (`tls`, `dns`, `raw_ip`) |
| `request.unknown_path` | 2 | `--columns` or filter path does not resolve |
| `packet.error` | 3 | literal on a derived field differs from `auto` in strict mode |

Diagnostic messages report the layer path, the received value, the expected format, and the remedy:

```
error[document.value_form]: ipv4.ttl: got `300`, expected an unsigned integer at most 255; use a value in range
help: match the field's declared data kind
```

## Migrating from v1

Use `packetcraftr convert` to upgrade `packetcraftr.packet/v1` documents to `packetcraftr.packet/v2`:

```console
$ packetcraftr convert --stdout packet.json
```

Use `--check` to verify whether files require conversion:

```console
$ packetcraftr convert --check examples/documents/packet-ipv4-udp.json
already v2 examples/documents/packet-ipv4-udp.json
converted 0, already v2 1, failed 0
```

`build` continues to accept v1 documents with a deprecation warning:

```console
$ packetcraftr build --packet-file packet.json
built 28 bytes
45 00 00 1c 00 00 00 00 40 11 f6 cd c0 00 02 01 c0 00 02 02 c0 00 00 09 00 08 bb d0
Warning document.deprecated_schema: packetcraftr.packet/v1 is deprecated; run `packetcraftr convert packet.json` to rewrite it as packetcraftr.packet/v2
```

## Negative Validation Example

A field value exceeding its maximum range produces a `document.value_form` error:

<!-- negative: document.value_form -->
```yaml
schema: packetcraftr.packet/v2
layers:
  - ipv4:
      ttl: 300
      source: 192.0.2.1
      destination: 192.0.2.2
  - udp:
      source_port: 49152
      destination_port: 9
```

Running `packetcraftr build` on this document outputs:

```console
$ cargo run -q -p packetcraftr-cli -- build --packet-file bad_ttl.yaml
error[document.value_form]: ipv4.ttl: got `300`, expected an unsigned integer at most 255; use a value in range
help: match the field's declared data kind
```

## JSON Schema

The formal JSON Schema for packet documents is located at [`schemas/packetcraftr.packet.v2.schema.json`](../schemas/packetcraftr.packet.v2.schema.json).

It is generated directly from the protocol codec registry:

```console
$ packetcraftr schema emit --contract packet/v2
```
