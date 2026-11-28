# Share hexadecimal byte pairs

## Context

Raw packet fields accept optional `0x` prefixes and whitespace, colon, or dash separators. Expression byte literals, UDP profile documents, and QUIC key logs require strict contiguous hexadecimal pairs. QUIC reports print connection identifiers and transport parameter bytes as compact lowercase hexadecimal. Each area previously carried pair decoding or printing logic that could drift.

## Decision

Core's field hexadecimal module owns strict pair decoding and compact lowercase printing. Raw keeps its input grammar by removing an optional prefix and separators before strict pair decoding. Expressions, key logs, and documents retain their strict syntax and existing errors. Size and generated-output limits stay at input boundaries before allocation.

## Alternatives

Treating all hexadecimal text as raw input would let separators into strict expressions, key material, and documents. Fixed-width identifiers, MAC groups, and number literals have separate grammars and remain outside this shared codec.
