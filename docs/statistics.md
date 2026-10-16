# Offline capture statistics

`analyze stats` reads PCAP/PCAPNG files, redirected stdin (`-`), and gzip or Zstd
captures. It defaults to the conversations table. Existing flat command aliases
and default table ordering are unchanged.

```sh
packetcraftr analyze stats capture.pcapng --table overview
packetcraftr analyze stats capture.pcapng --table conversations --sort bytes --top 10
packetcraftr --output csv analyze stats capture.pcapng --table endpoints
```

## Overview and accounting

`--table overview` collects protocols, endpoints, and conversations in one pass,
without retaining port or I/O tables. Text and JSON report matched/read frames,
matched captured bytes, earliest/latest matched timestamps, duration, average
captured packet size, packet/byte rates, interfaces, and total distinct protocols,
endpoints, and conversations. Empty matches omit timestamps, duration, averages,
and rates in JSON; a zero-duration match omits rates.

A [complete JSON example](../examples/documents/output-stats-overview-success.json)
uses the bundled `http-stream.pcap` capture.

Overview retains five entries per leaderboard by default. `--top N` applies
independently to each leaderboard; `--top 0` retains totals only. Counts are
computed before truncation, with a separate omission diagnostic for each list.
Resource diagnostics report the effective `--top`; explicit flags take priority
and resource presets keep their existing limits. The v1 presets do not set `--top`.

JSON uses the existing statistics envelope and row types, with `table: "overview"`,
`protocol_count`, `endpoint_count`, `conversation_count`, and the `protocols`,
`endpoints`, and `conversations` arrays. `interfaces` retains capture-global
interface order; its length is the interface count.

Protocols count each protocol once per matched frame, charging its full captured
length. Endpoint totals combine transmitted and received traffic, so a frame may
contribute to two endpoints. Conversations combine both directions and retain
capture-global stream identifiers and scope. Filtering does not renumber streams.
Fragment accounting is capture-global. See [resource accounting](analysis-resources.md).

## Ordering and row limits

`--sort frames|bytes` ranks rows descending by that metric, then descending by the
other metric, then ascending by the natural key:

| Table | Natural key |
| --- | --- |
| Protocols | Protocol name |
| Endpoints | IP address |
| Conversations | Transport, then capture-global stream index |
| Ports | Transport, then port number |
| I/O | Bucket offset |

Conversations and endpoints rank by combined directional counts. Sorting happens
before `--top`. Overview defaults to frame ranking, including the byte tie-breaker.
Without `--sort`, protocols keep frame count/name ordering; conversations,
endpoints, and ports keep natural order unless `--top` requests their busiest rows
by frames, then bytes. I/O keeps chronological order even with `--top`.
`--sort` is rejected for fragments before opening the capture.

## CSV contract

`--output csv` supports conversations, endpoints, protocols, ports, and I/O only.
Other commands and overview/fragments reject CSV before reading input. Output is
UTF-8 without a BOM, comma-separated, with CRLF record endings. Fields containing
commas, quotes, or line breaks are quoted; embedded quotes are doubled. Empty
results emit the header. Diagnostics and errors go to stderr, leaving stdout
exclusively CSV. Row order and `--top` match the corresponding JSON report.

Headers preserve the declared output row field order:

| Table | Header |
| --- | --- |
| Conversations | `transport,stream,scope_id,scope_interface,scope_encapsulation,address_a,port_a,address_b,port_b,frames_a_to_b,bytes_a_to_b,frames_b_to_a,bytes_b_to_a,first_timestamp,last_timestamp,duration` |
| Endpoints | `address,tx_frames,tx_bytes,rx_frames,rx_bytes` |
| Protocols | `protocol,frames,bytes` |
| Ports | `transport,port,frames,bytes` |
| I/O | `origin,underflow_frames,interval,offset,frames,bytes` |

Counts and byte sizes are unsigned decimal integers. Timestamps are signed Unix
seconds with exactly nine fractional digits (for example `-0.500000000`);
durations, intervals, and offsets are seconds with exactly nine fractional digits.
Missing optional values use empty cells. Scope encapsulation is compact JSON
inside its quoted CSV cell; an empty path is `[]`. I/O repeats origin, underflow
frame count, and interval on every bucket row.

Analysis completes before CSV publication starts. Cancellation and deadlines are
checked during analysis and between output records. Output failures return a
nonzero exit status and may leave a partial CSV file. As with other synchronous
outputs, a blocked write may delay cooperative checks.

## Public API and versioning

`packetcraftr_core::analysis::stats::Table` and
`packetcraftr_cli::output::stats::Table` gain `Overview`;
`output::stats::TableData` gains an `Overview` variant using the existing row types.
Core `stats::Report` gains `protocol_count`, `endpoint_count`, and
`conversation_count`, recording totals before presentation truncation.
`packetcraftr_cli::output::contract::Format` gains `Csv`.

Current JSON/NDJSON producers use `output::contract::SCHEMA_V18`
(`packetcraftr.output/v18`); v17 introduced the overview and ordering contract. The v16
schema and historical examples remain frozen. See [consumer compatibility](consumer-compatibility.md).
