# netio holds only provider contracts and native adapters

`packetcraftr-netio` owns the capability contracts (route, interface, capture,
transmit, TCP connect), their system providers, and the native backends behind
them. Route planning, neighbor resolution, and their caches belong to
`packetcraftr`. They interpret packets and make decisions, and neighbor
resolution is active discovery that needs authorization, so none of them is
native I/O. Keeping them out of netio leaves the unsafe crate small and lets
live policy see every decision that leads to traffic.

## Considered Options

- **netio as "network plumbing"**, keeping the planner, resolver, and caches
  next to the providers. Rejected because it spreads packet interpretation and
  active discovery across two crates. It also re-checks the same route rules in
  the planner, the normalizer, and a backend.
