# M13: SCTP and IP-protocol inventory

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M5](m05-host-discovery.md), [M6](m06-port-planning-inference.md) | Additional typed scan/discovery families |

Core has SCTP codec/tag building blocks, not an SCTP scanner. Existing TCP/UDP
port and echo requests do not provide selected IP-protocol inventory.

## Intended behavior

- Add SCTP INIT and COOKIE-ECHO diagnostics with bounded typed correlation chunks,
  verification-tag handling, positive/negative/ambiguous observations, and exact
  retained malformed/unknown bytes. Codec presence is not workflow support.
- Represent IP-protocol numbers separately from transport ports. Define bounded
  selection and correlated replies/ICMP errors without inventing port identities.
- Add explicitly selected ACK, ICMP timestamp/netmask, SCTP, and IP-protocol
  discovery. No implicit extra probes; composed discovery shares exclusions,
  authorization, pacing, duration, and packet/byte/evidence ceilings.
- Unsupported capabilities fail typed. Silence, unrelated errors, and
  operational failure never imply a certain protocol/port state.

## Decisions before implementation

Set minimal SCTP chunks, mode correlation and inference matrices, endpoint keys,
IP-protocol selection/payload policy, extra discovery eligibility, and machine
representations. Choose families/platforms that can be honestly supported;
separate implementation from acceptance. New datasets require independent
version/provenance review, not copied scanner data.

## Acceptance gates

Independent dual-stack fixtures cover positive, closed/blocked, silent, malformed,
unrelated, contradictory, duplicate, late, and reordered cases. Verify checksum/tag
and quoted-packet correlation, identity, finite preparation/retention, final policy,
and discovery exclusions. Retain exact-revision native runs for supported
platform/profile combinations under [M2](m02-ground-truth-benchmarks.md) and
[M3](m03-native-validation.md).

Keep [evidence](../scanner-evidence.md),
[data policy](../scanner-data-policy.md), schemas, examples, and migration aligned.
M13 stays **Planned**, not equivalent to codec coverage.
