# Share command declarations between parsing and publication

## Context

Output formatting depended on the command registry to read published IDs and supported formats. The registry depended on output to define those formats, so both sat in the same dependency cycle.

## Decision

The command catalog declares each parser path, argument type, help entry, stable ID, and format list in one place. The parser expands the dispatch and help fields. The output contract expands only the ID and format fields. Output payload declarations stay beside each command's payload types. The CLI has no upward layer exceptions.

## Alternatives

A separately maintained enum or format table would duplicate published commands and make additions depend on matching entries across two places. Keeping the output-to-registry edge would preserve the cycle and require the output contract to depend on command implementations.
