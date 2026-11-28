# Enforce cycle policy at documented module boundaries

## Context

The layer checker enforces dependency direction, but two modules at the same layer can acquire a cycle without changing any layer. A separate dependency scanner could classify the same reference differently from the existing check.

## Decision

Use the longest documented module boundary for both direction checks and the production graph. Reject every group of mutually reachable boundaries unless its exact membership is documented in the crate root. Report stale entries when a cycle is removed or changes membership. Core's packet model and netio's system provider dispatch are the two existing groups. The original upward edge rules still apply inside those groups.

`--graph` prints the same graph in DOT format. Its scope is explicit Rust source references across production feature gates. Cargo separately checks cycles between packages.

## Alternatives

Requiring an order within every layer would prohibit valid one-way dependencies and force unnecessary layer splits. Approving individual edge pairs would duplicate the existing upward edge rules and would not describe the larger unit those modules already form.
