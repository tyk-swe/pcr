# CLI output types own every published field

The CLI owns the versioned machine-output contract. Its output types embed a
library type only when that type is itself a versioned contract (the
`packetcraftr.packet` document). Every other published field uses a CLI-owned
type with the same JSON shape, built with `From`/`TryFrom`. The duplication is
deliberate: a serde change in a library must not silently change a frozen
output family.

## Consequences

Library serde derives are not output commitments. The v6 conformance suite
proves that the mirrored types keep the published shape.
