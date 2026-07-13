# Migrating structured output from v1 to v2

PacketcraftR 0.3 removes `packetcraftr.output/v1`; there is no compatibility switch. Packet documents remain `packetcraftr.packet/v1`.

## Envelope changes

Every aggregate JSON object now identifies `packetcraftr.output/v2` and contains:

- `tool.version` and `tool.build_target`
- a 32-hex `operation_id`
- `command`, `mode`, and `effective_request`
- `status` plus exactly one `result` or `error`
- `completion_reason`, `diagnostics`, and optional `stats`

Errors add a recovery-oriented `category` alongside the stable `kind`, code, message, causes, remediation, and exit family. Consumers should branch on `code` and `category`, not English text.

All sequences, seeds, Unix seconds, byte counters, lengths, layout offsets, diagnostic indexes, and other 64-bit or platform-sized integer values serialize as decimal strings. Nanoseconds and inherently narrower protocol values remain JSON numbers. Durations are objects with decimal-string `seconds` and numeric `nanoseconds`.

## NDJSON lifecycle

An NDJSON consumer must accept this state machine:

```text
start(sequence="0") -> item* -> complete | error | cancelled
```

`start` is flushed before work begins. Item records are flushed as batches, hops, attempts, cases, or frames complete. There is exactly one terminal record and its sequence follows the preceding emitted record. A late `error` or `cancelled` terminal does not invalidate already processed items.

Do not wait for process exit before reading stdout. Parse each line independently, reject a second terminal record, and persist the operation ID with every derived observation.

## Evidence changes

Frame bytes are retained once and hexadecimal is generated only during serialization. Human output is a 128-byte preview. Aggregate exact evidence defaults to 16 MiB and reports `evidence_complete=false` when later raw frames are omitted. Replay aggregate JSON is a summary rather than an unbounded frame list. Select NDJSON, raw/hex, PCAP, or PCAPNG when exact per-frame evidence is required.

## Migration checklist

1. Replace the v1 schema with the immutable v2 schema from the matching release tag.
2. Update envelope parsing before updating command-specific results.
3. Parse decimal strings with checked 64-bit/platform-independent arithmetic.
4. Implement the NDJSON lifecycle and flush-aware incremental processing.
5. Handle `cancelled` separately from ordinary errors and recognize exits 130 and 143.
6. Test against every committed document in `examples/documents`.
7. Preserve packet-document v1 handling unchanged.

The public output-v2 surface is frozen for the 0.3 qualification period. A breaking discovery requires a 0.4 release and restarts qualification; 1.0 promotes the qualified contract unchanged.
