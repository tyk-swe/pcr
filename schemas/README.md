# Versioned JSON schemas

PacketcraftR publishes JSON Schema draft 2020-12 documents for formats that are intended for automation.

| Identifier | Schema | Purpose |
| --- | --- | --- |
| `packetcraftr.packet/v1` | [packetcraftr.packet.v1.schema.json](packetcraftr.packet.v1.schema.json) | Ordered packet documents using tagged reflective `FieldValue` objects |
| `packetcraftr.output/v1` | [packetcraftr.output.v1.schema.json](packetcraftr.output.v1.schema.json) | Aggregate JSON results and individual NDJSON records |

The value of a document's `schema` property is the PacketcraftR format identifier. The JSON Schema meta-schema URI remains in the schema file's `$schema` property; it is not accepted as an extra property in a `PacketDocument`.

Packet documents deliberately do not enumerate protocols or field names. A `ProtocolRegistry` is extensible, so it performs protocol-specific field, range, layer-binding, and required-field checks after structural schema validation. Parser byte/layer/depth limits are runtime policy and are not relaxed by a document passing JSON Schema validation.

An output success envelope contains `result` and no `error`; an error envelope contains `error` and no `result`. Each line emitted by an NDJSON command is a complete `packetcraftr.output/v1` object and uses `sequence` to preserve stream order. `diagnostics` is always an array, including when empty.

Examples are in [examples/documents](../examples/documents). Validate them with a draft 2020-12 implementation, for example:

```console
jsonschema schemas/packetcraftr.packet.v1.schema.json \
  --instance examples/documents/packet-ipv4-udp.json

jsonschema schemas/packetcraftr.output.v1.schema.json \
  --instance examples/documents/output-build-success.json \
  --instance examples/documents/output-build-error.json \
  --instance examples/documents/output-capture-event.json
```
