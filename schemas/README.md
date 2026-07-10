# Versioned JSON schemas

PacketcraftR publishes JSON Schema draft 2020-12 documents for formats that are intended for automation.

| Identifier | Schema | Purpose |
| --- | --- | --- |
| `packetcraftr.packet/v1` | [packetcraftr.packet.v1.schema.json](packetcraftr.packet.v1.schema.json) | Ordered packet documents using tagged reflective `FieldValue` objects |
| `packetcraftr.output/v1` | [packetcraftr.output.v1.schema.json](packetcraftr.output.v1.schema.json) | Aggregate JSON results and individual NDJSON records |
| `packetcraftr.fixture-provenance/v1` | [packetcraftr.fixture-provenance.v1.schema.json](packetcraftr.fixture-provenance.v1.schema.json) | Hash, source/license, semantic expectation, capture metadata, and review evidence for each authoritative test fixture |

The value of a document's `schema` property is the PacketcraftR format identifier. The JSON Schema meta-schema URI remains in the schema file's `$schema` property; it is not accepted as an extra property in a `PacketDocument`.

Packet documents deliberately do not enumerate protocols or field names. A `ProtocolRegistry` is extensible, so it performs protocol-specific field, range, layer-binding, and required-field checks after structural schema validation. Parser byte/layer/depth limits are runtime policy and are not relaxed by a document passing JSON Schema validation.

An aggregate success envelope contains `result` and no `error` or `sequence`;
an aggregate error contains `error` and no `result` or `sequence`. Both carry
`"mode": "aggregate"`. Each NDJSON line is a complete
`packetcraftr.output/v1` object with `"mode": "stream"` and a zero-based
`sequence`. Terminal stream errors use the next unused sequence, including
sequence zero when the stream fails before its first result. `diagnostics` is
always an array. When `stats` is present, its required `capture` object reports
received and dropped frames/bytes plus queue-overflow events; non-zero loss is
also represented by a diagnostic or typed error according to the selected
overflow policy.

Success schemas correlate `command` with a command-specific `result`; a
well-formed frame result is therefore invalid for `build`, for example. The
Rust equivalents are the public `AggregateOutput<T>`, `StreamRecord<T>`,
`OutputError`, and per-command result types in `packetcraftr::output`. CLI
operations construct these types once, and text, JSON, NDJSON, hex, and raw
renderers consume the same result rather than recreating a wire shape. Commands
that support both JSON and NDJSON have separate aggregate and per-item result
types, so a stream never repeats an aggregate summary as an event.
`capture` emits zero or more `frame` events followed by one `complete` event
carrying the frame count and final statistics. `exchange` emits `sent`,
`response`, `unanswered`, `unsolicited`, or `undecoded` evidence events before
its final `complete` event. `scan` emits one `port` event per resolved endpoint,
bounded `undecoded` evidence events, and a final `complete` event. A runtime
failure replaces the next event with a terminal error at the next unused
sequence.

## Command/format matrix

The matrix is also published as `COMMAND_OUTPUT_CONTRACTS`. Unsupported
combinations fail with `cli.output_format` before file, provider, resolver,
route, capture, or send side effects. Capability-gated commands still return a
capability error until their implementation issue lands.

| Command | Formats |
| --- | --- |
| `build`, `dissect` | text, JSON, whole-frame hex, raw |
| `plan`, `interfaces`, `routes` | text, JSON |
| `send` | text, JSON, whole-frame hex, raw, PCAP, PCAPNG |
| `exchange` | text, JSON, NDJSON, PCAP, PCAPNG |
| `capture` | text, NDJSON, whole-frame hex, PCAP, PCAPNG |
| `read` | text, NDJSON, whole-frame hex, PCAP, PCAPNG |
| `replay` | text, JSON, NDJSON, PCAP, PCAPNG |
| `scan`, `traceroute`, `dns`, `fuzz` | text, JSON, NDJSON |

Error objects use stable machine `code` and broad `kind` values matching the
documented exit classes. A classified live failure may add a non-empty
`remediation` string. JSON escaping preserves control-bearing source values for
machines; terminal-safe text rendering is a separate presentation rule.

Examples are in [examples/documents](../examples/documents). Validate them with a draft 2020-12 implementation, for example:

```console
jsonschema schemas/packetcraftr.packet.v1.schema.json \
  --instance examples/documents/packet-ipv4-udp.json

jsonschema schemas/packetcraftr.output.v1.schema.json \
  --instance examples/documents/output-build-success.json \
  --instance examples/documents/output-build-error.json \
  --instance examples/documents/output-capture-event.json \
  --instance examples/documents/output-exchange-event.json \
  --instance examples/documents/output-replay-success.json \
  --instance examples/documents/output-scan-success.json \
  --instance examples/documents/output-scan-event.json \
  --instance examples/documents/output-scan-complete.json
```

CI also requires every document in `tests/fixtures/invalid-output` to fail
validation. Those fixtures freeze aggregate/stream separation, mandatory
stream sequencing, and command-specific result shapes.

Every non-example file in `tests/fixtures` has a
`<fixture>.provenance.json` sidecar. CI validates those documents against the
fixture-provenance schema, recomputes each SHA-256, binds each declared path to
its sidecar name, and enforces sidecar changes over the complete pull-request
or push range. See the [fixture and provenance policy](../tests/fixtures/README.md).
