---
status: accepted
---

# Capture parts retain all source metadata

For the [capture splitting specification](../../.scratch/capture-split/spec.md), each part is equivalent to selecting a contiguous physical-frame range with `capture_file::select`: every source metadata record is retained, packet records remain exact, and PCAPNG section lengths become unknown. Rebuilding parts through `Writer` or retaining only the active interface descriptions was rejected because it would discard unknown metadata or change the source's interface-numbering context. The deliberate cost is bounded metadata duplication and a seekable snapshot; the feature is specified, not implemented.

## Consequences

Interface statistics describe the source capture, even in a small part. Cumulative metadata and total output ceilings bound amplification. Part boundaries do not imply complete streams or IP datagrams; dependency-preserving selection remains `export`'s responsibility.
