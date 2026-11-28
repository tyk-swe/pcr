# Use the existing crate boundaries for architecture governance

## Context

The four workspace libraries and binary already define the main dependency direction. Their crate-root layer tables drive the repository's production source checks. Recent boundary changes in commits `f5303f39f` and `87202d58a` established separate ownership for packet mechanics, native I/O, live policy and spending, and CLI publication.

## Decision

Use the existing crate structure and documented module boundaries. Keep the architecture inventory and batch records in this directory. Define any additional enforced dependency constraint against the same layer tables where the existing source scanner can support it. Keep the machine schema and published contract identifiers authoritative for external compatibility.

## Alternatives

Moving modules into new crates would add dependency boundaries, but also require broad API migration before it resolved the identified CLI cycles. A second checked-in layer policy would duplicate the definitions already enforced in CI. Continue with the existing declarations and consider a new boundary when a concrete ownership problem calls for one.
