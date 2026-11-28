# Convert shared analysis settings in the core

## Context

Collector sessions and direct pipeline callers share input selection, cancellation, and resource settings. The CLI and core each mapped these fields into pipeline options. Collector needs also control indexing, TCP event delivery, and provenance tracking.

## Decision

Core owns the conversion from `SessionOptions` into `Options`. The conversion sets the default direct pipeline plan, with TCP events and source tracking disabled. A session overrides those three fields from its collector. Direct callers can still explicitly set a plan, including inventory's physical analysis plan. The conversion exhaustively reads the caller fields so adding one requires revisiting the mapping.

## Alternatives

Collapsing the two public option structs would change their callers' contracts and expose pipeline internals to collector setup. Keeping both field mappings would leave new caller settings to be wired in two places.
