# Report capture totals from their owners

## Context

Both normalization formats counted selected frames and bytes after writing each packet. The writer already tracks successful writes. The input budget counts every physical frame, including frames skipped by the selection.

## Decision

Both format paths use one finalization step. It flushes output before returning the writer's format and committed totals alongside the input budget's totals. PCAP still opens on the first selected frame and requires one interface. PCAPNG still maps selected interfaces as it writes.

## Alternatives

Sharing a third counter between both paths would still duplicate writer accounting. Merging the writing loops would mix two different interface and timestamp rules. The report shares only the semantics common to both formats.
