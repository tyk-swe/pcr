# Document upward dependency approvals in crate roots

## Context

The netio layer table explained why system providers dispatch to native backends. The precise source and target prefixes for those dependencies lived in a Python allowlist.

## Decision

List permitted upward dependencies beside the layer table and cycle approval. The checker reads each source and target as a path prefix and rejects unused approvals during production scans. Cycle approval still requires an exact match with a group in the production graph.

## Alternatives

Keeping the exceptions in Python would require checking two sources before changing a crate boundary. Deriving upward permissions from a cycle approval would also grant unrelated dependencies inside the approved group.
