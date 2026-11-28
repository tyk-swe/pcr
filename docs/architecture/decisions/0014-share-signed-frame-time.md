# Share signed frame time decomposition

## Context

Filters compare signed Unix timestamp components, capture writers encode them, and the CLI publishes them in machine output. Each consumer needs the same floored decomposition for times before the Unix epoch. The CLI previously repeated the split while converting into its timestamp type.

## Decision

Core's `frame::unix_floor` returns whole seconds as `i128` with nanoseconds as `u32`, without narrowing the representable clock range. Filters, PCAPNG encoding, and CLI output use this split. The CLI owns conversion into its published `i64` range and its text format.

## Alternatives

A shared wire timestamp type would couple core filtering and capture encoding to the CLI output schema. Unsigned-only clocks have different semantics and cannot represent pre-epoch capture timestamps.
