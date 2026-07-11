# ADR 0005: Active neighbor resolution

- Status: Accepted
- Date: 2026-07-10

## Context

Passive route planning can select an interface, interface-owned source, next hop, link type, and MTU, but it cannot supply the destination MAC needed for a Layer 2 frame. Consulting an operating-system neighbor table alone cannot produce deterministic attempts or captured evidence, and resolving the final IP instead of the route's next hop sends off-link traffic to the wrong link-layer address. Discovery must also keep spoofed packet fields out of ARP/NDP and must not silently change the selected route or link mode when it fails.

## Decision

Planning remains side-effect free. For an on-link destination it records that destination as the neighbor target; for an off-link route it records the gateway. `RoutePlanner::materialize` is the explicit active boundary. It passes a `NeighborRequest` containing the selected interface, interface-owned IP and MAC, neighbor target, ordered VLAN stack, MTU, and open link type. Explicit packet source fields are not part of that request.

`ActiveNeighborResolver` composes independently injectable interface, Layer 2 send, and capture providers. `SystemNeighborResolver` selects their native implementations. It arms capture and crosses its readiness barrier before the first request, validates complete sends, performs at most three one-second attempts by default, and stops and joins capture on every result. IPv4 uses Ethernet/IPv4 ARP as specified by [RFC 826](https://www.rfc-editor.org/rfc/rfc826). IPv6 uses solicited-node multicast from [RFC 4291](https://www.rfc-editor.org/rfc/rfc4291) and validates Neighbor Solicitation/Advertisement requirements from [RFC 4861](https://www.rfc-editor.org/rfc/rfc4861), including hop limit, checksum, target, flags, and link-layer address options.

Requests and replies carry the exact planned VLAN stack. Replies from a different interface or VLAN, frames captured before the first request, malformed messages, and messages that do not correlate to the source and target cannot satisfy a lookup. They remain bounded evidence. A successful result always retains its matching frame, evicting older unrelated evidence if necessary. Failure returns attempts, retained frames, evidence-truncation state, and capture statistics. There is no route, link-mode, or destination fallback.

Successful mappings enter a resolver-owned cache. The default lifetime is 30 seconds and the default maximum is 4,096 entries. The key includes interface identity, interface-owned source IP and MAC, target, VLAN stack, and link type. Expired entries are removed before lookup or insertion, oldest entries are evicted at the bound, and callers can clear the cache. Failures are never cached.

Neighbor materialization changes only fixed-width Ethernet address fields. The high-level client rebuilds and retains the final bytes, rejects a shape change, and repeats permissive-build and traffic-policy byte checks before transmission. Resolution evidence remains attached to `MaterializedRoute` and therefore to send results.

## Consequences

- Dry planning is safe for inspection and policy checks; callers can see the intended next hop without emitting traffic.
- Active discovery has explicit time, attempt, memory, cache, and cleanup bounds.
- Captured evidence and native loss counters make both success and exhaustion auditable.
- VLAN, low-MTU, unsupported-link, missing-source, dependency, permission, and cleanup failures remain typed errors.
- Privileged cross-platform integration evidence is required before live capability claims.

## Alternatives considered

### Read only the operating-system neighbor cache

Rejected because a miss has no bounded active behavior or captured proof, and cache state differs nondeterministically across platforms.

### Resolve the final destination and fall back to Layer 3

Rejected because off-link Ethernet must target the gateway and a fallback would change caller intent after policy and route selection.

### Use packet-supplied source fields for discovery

Rejected because crafted or spoofed identities need not belong to the selected interface and can make replies unroutable or ambiguous.
