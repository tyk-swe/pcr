---
status: accepted
---

# HTTP artifacts and timing preserve observed evidence

For the [offline investigation specification](../../.scratch/offline-investigation/spec.md), HTTP body artifacts remove chunk framing while preserving content encodings and remaining transfer codings, and transaction timing records the physical capture observation that made each header boundary available to the parser. Decompression and timestamps inferred from the earliest contributing source frame were rejected: decompression changes the artifact's bytes, while reassembled delivery provenance cannot establish an exact per-octet wire timestamp. These are decisions for the specified future features; this ADR does not claim they are implemented.

## Consequences

An artifact may still contain gzip bytes; its report identifies the message and hashes the exact exported bytes. A gap-filling packet can make earlier bytes available, and clock regressions remain signed intervals. HTTP header association and body completeness remain separate evidence.
