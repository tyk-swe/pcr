# Architecture decision records

Architecture decision records (ADRs) capture decisions that constrain PacketcraftR v0.2. They explain why public contracts exist and are not substitutes for API documentation.

| ADR | Status | Decision |
| --- | --- | --- |
| [0001](0001-portable-kernel-and-registry.md) | Accepted | Portable packet kernel, immutable registry, and stable root façade |
| [0002](0002-wire-intent-and-live-safety.md) | Accepted | Strict/permissive building and the second live opt-in |
| [0003](0003-capture-and-exchange-ownership.md) | Accepted | Capture records, readiness barrier, and one owned receive stream |
| [0004](0004-component-and-native-adapter-boundaries.md) | Accepted | Component DAG, provider seams, native dependency ownership, and unsafe policy |
| [0005](0005-active-neighbor-resolution.md) | Accepted | Gateway-aware ARP/NDP, correlation, evidence, and cache ownership |
| [0006](0006-native-raw-ip-transmission.md) | Accepted | Exact-byte raw IPv4/IPv6 transmission and kernel rewrite handling |
| [0007](0007-typed-cli-output-contracts.md) | Accepted | Typed aggregate/stream envelopes, result contracts, and format matrix |

New ADRs use the next four-digit number and include status, context, decision, consequences, and alternatives. Amend a decision with a superseding ADR instead of rewriting its history after release.
