# ADR 0007: Typed CLI output contracts

- Status: Accepted
- Date: 2026-07-10

## Context

The first CLI commands assembled JSON with command-local `json!` values.
The common schema accepted any object or array as `result`, and `read` used
`--output json` to emit multiple compact JSON values. That made the meaning of
JSON depend on the command, allowed one command's result shape to pass as
another's, and left no type-level rule requiring sequence numbers on terminal
stream errors. Copying that pattern into live and tool commands would force a
cross-command rewrite as more workflows were added.

Text, JSON, NDJSON, whole-frame hex/raw, PCAP, and PCAPNG also have different
cardinality and byte-preservation rules. A renderer must not infer a result by
parsing logs or recreate a command-specific object independently from the
operation that produced it.

## Decision

The root facade owns a public `output` module. `AggregateOutput<T>` represents
one JSON success or error and has no sequence field. `StreamRecord<T>`
represents one independently valid NDJSON success or terminal error and always
has a `u64` sequence. Both use the same `OutputError`, diagnostics, optional
operation statistics, command identifier, schema identifier, and explicit
mode. Constructors keep status, result/error exclusivity, mode, and sequence
presence out of caller control.

Each command has a deliberate result type.
Commands that offer both JSON and NDJSON also have a separate per-item stream
result type.
`build`, `dissect`, `read`, `replay`, and `interfaces` construct those results before
selecting a renderer. Complete bytes remain available to hex/raw renderers but
serialize only through explicit hexadecimal fields. Capture timestamps use
signed Unix seconds plus nanoseconds so PCAPNG records before the Unix epoch do
not fail during JSON serialization.

`read` may stream the same bounded records to PCAP/PCAPNG without constructing
JSON. `replay` emits one exact transmitted-frame result per NDJSON success and
a terminal replay result, while aggregate JSON retains a bounded collection of
the same frame result. Its PCAP/PCAPNG renderers contain only backend-confirmed
successful frames.

`OutputFormat`, `CommandName`, and `COMMAND_OUTPUT_CONTRACTS` define one shared
format matrix. The CLI rejects an unsupported combination with the classified
`cli.output_format` error before command I/O. JSON means one aggregate object;
NDJSON is a separate explicit format. Stream successes begin at sequence zero,
and a terminal error uses the next unused sequence. A failure before the first
success is sequence zero.

The `packetcraftr.output/v1` JSON Schema correlates every successful command
with its result definition and separately validates aggregate successes,
aggregate errors, stream successes, and stream errors. Positive published
examples and intentionally invalid negative fixtures are both CI gates.

## Consequences

- Adding a command requires a typed result, a matrix entry, and a schema
  correlation; it does not require redesigning the common envelope.
- Aggregate JSON consumers receive exactly one value, while line-oriented
  consumers can validate and order every NDJSON record independently.
- Interface output is an object containing an `interfaces` collection instead
  of a bare, weakly identified array.
- `read --output json` is rejected; callers must choose `--output ndjson`.
- `read` and `replay` capture-file output is an explicit matrix entry and
  remains subject to the same operation limits as text/structured rendering.
- Adding a new format to an existing command is an explicit contract change.

## Alternatives considered

### Keep a permissive `result` object

Rejected because schema validation would prove only the envelope spelling, not
that a consumer received the requested command's result.

### Infer streaming from the command name

Rejected because several commands support both aggregate summaries and
event streams, and terminal failures still need an unambiguous sequence rule.

### Let each renderer construct its own result

Rejected because text, structured, and byte renderers could diverge about the
operation's bytes, diagnostics, route evidence, or statistics.
