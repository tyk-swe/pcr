# Report the writer's byte delta for capture rewrite

## Context

Mapping counted output bytes in its report after each packet write. The writer already charges the committed byte budget for ordinary packets and for preserved PCAPNG packet blocks. The public mapping API can receive an existing writer.

## Decision

Calculate the report's written bytes from the change in the writer's committed count. Leave read limits and frame identity checks with the mapping operation. The existing writer test also runs an empty mapping after a nonempty one to check that it reports zero new bytes.

## Alternatives

Using the absolute writer count would include writes from earlier operations. Keeping a second count would allow the report and the writer budget to diverge as packet formats evolve.
