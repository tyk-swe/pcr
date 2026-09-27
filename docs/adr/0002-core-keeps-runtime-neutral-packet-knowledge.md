# Core keeps runtime-neutral packet knowledge, not live policy

`packetcraftr-core` keeps packet knowledge that needs no runtime, even when only
live workflows use it today: response matchers and packet semantics such as
destinations and paths. Vocabulary that only makes sense under live policy
lives in `packetcraftr`: live opt-in and reasons transmission is denied.
Live-only deadline helpers move to the lowest crate that uses them: netio's
`deadline` module for those netio uses, `packetcraftr` for the rest.
Probe/attempt coordinates stay in core: they are classification vocabulary,
and their published keys are frozen. Error kinds in core are neutral (for
example usage, never CLI), and the CLI maps each kind to its published prefix.

## Considered Options

- **Move everything that only live workflows use.** Rejected: matchers and
  packet semantics are pure functions over packets, and offline analysis is a
  natural future user. Moving them up would make core's contents depend on who
  happens to call it today.
- **Move probe/attempt coordinates to `packetcraftr`.** Rejected: they are
  variants of core's error `Coordinate`, one classification vocabulary whose
  serialized keys are part of the frozen output envelope.
