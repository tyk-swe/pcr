# CLI contract

The command grammar consists of exactly these 14 commands:

```text
build       dissect      plan         send         exchange
capture     read         replay       scan         traceroute
dns         fuzz         interfaces   routes
```

`packetcraftr --help` and each `packetcraftr COMMAND --help` define the
option names, value spellings, conflicts, finite defaults, and help text. CI
compares them with `tests/golden/cli-help.txt`; it also tracks `--version` and
the canonical text parse-error rendering. Every command has an implemented
path. A build without the required native feature, runtime, device, or
privilege returns a typed capability error and never changes link mode or
bytes as a fallback.

## Packet recipes

Commands that accept a packet recipe require exactly one of `--packet`,
`--packet-file`, or non-empty standard input. `--packet` is the bounded
expression grammar. Files with `.json`, `.yaml`, or `.yml` select the versioned
packet-document parser; standard input is detected from its first non-space
token. Input is capped at 16 MiB before UTF-8 decoding or parsing; documents are
capped at 64 layers and 64 recursive list levels. Supplying an explicit recipe
while piping another is an error rather than silently ignoring one source.

## Output and streaming

`--output` is global and accepts `text`, `json`, `ndjson`, `hex`, `raw`, `pcap`,
or `pcapng`. Each command supports only the combinations in the
[command/format matrix](../schemas/README.md#commandformat-matrix), checked
before file or live side effects.

JSON is one aggregate `packetcraftr.output/v1` success or error and never has a
sequence. NDJSON is a stream of independently valid v1 objects, every one with
a zero-based sequence. A terminal error uses the next unused sequence; an
item-specific error retains that item's sequence. Hex, raw, PCAP, and PCAPNG
always represent complete frames. Display truncation never changes retained or
capture-file bytes.

## Exit codes

| Code | Stable class |
| ---: | --- |
| 0 | Success, `--help`, or `--version` |
| 2 | CLI grammar, recipe, limit, or document/schema validation |
| 3 | Packet build, dissection, capture-record, or replay-input failure |
| 4 | Unsupported capability, missing native dependency, or privilege |
| 5 | Route, neighbor, send, capture, timeout, cleanup, or other runtime I/O |
| 6 | Traffic-policy denial |
| 70 | Internal provider or output invariant failure |

Structured errors also carry a stable machine `code` and broad `kind`. The Rust
`FailureCategory` provides the finer validation/capability/policy/timeout/I/O/
cleanup/invariant distinction without changing these process exit classes.

## Platform variance

Portable parsing, packet bytes, help, schemas, output envelopes, and exit-code
classification are target-independent. Only documented adapter facts may vary:
available interfaces/routes, selected native path, timestamps, OS diagnostics,
and whether the explicitly requested live capability is installed and
authorized. Cross-platform CI runs the same golden and behavior tests on Linux,
macOS, and Windows.

## Compatibility review

`scripts/check-cli-contract.py` compares this contract, the packet and output
schemas, and the help, parse-error, and version goldens. Any command, option,
default, conflict, value spelling, exit class, packet mapping, output shape, or
schema change must update the corresponding golden or schema after explicit
compatibility review.
