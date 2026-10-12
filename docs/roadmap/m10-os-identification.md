# M10: OS identification

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M5](m05-host-discovery.md), [M7](m07-adaptive-scheduling.md) | Qualified remote stack observations |

The first increment implements standalone `identify-os` and `Client::identify_os`,
original bounded IPv4/IPv6 probes, prerequisite verification, explicit omissions
and contradictions, pure fingerprint extraction/matching, and output/v14.
See the [user/library guide](../os-identification.md).

## Implemented decisions

- One numeric unicast target; explicit distinct open/closed TCP ports. Required
  open SYN/ACK and closed RST/ACK evidence is verified before additional probes.
- Versioned four-probe set; random operation correlation identities, bounded
  attempts, shared pacing/deadline/budgets, strict final-wire authorization,
  bounded neighbor preparation, and exact RST cleanup.
- Retained observations and candidates stay separate. Required evidence cannot
  be supplied by late/unrelated/router replies or withheld capture bytes.
  Missing, malformed, conflicting, and intermediary-modified evidence remains
  unknown or inconclusive.
- Fully satisfied stable predicates qualify Linux/Windows/macOS families.
  Competing families remain ambiguous; confidence is ordinal. No release,
  authenticated identity, inferred initial TTL, or probability is claimed.
- Original independently versioned corpus, named maintainer, provenance and
  pre-tuning training/hold-out split. No Nmap data or derived signatures.

## Evidence and remaining acceptance

[Preserved evidence](evidence/m10/README.md) contains original Linux 7.0.0-38
training captures and a frozen independent 7.0.0-34 kernel hold-out. The two
bundled Linux Ethernet profiles qualify all four suitable dual-stack/format
hold-out case-runs; all eight unsuitable cases remain inconclusive. These are
repeated cases from one held-out build, not twelve independent OS instances.
Other-family false-positive accuracy and broad Linux coverage remain unmeasured.

Injected tests cover known/unknown/ambiguous, partial, contradictory, unsuitable,
late, wrong-identity, and modified observations. Native tests exercise real
immediate kernel replies and JSON/NDJSON over isolated documentation-address
links. Capture loss, offload, retention, timing, source/binary identity, and
unsupported profiles must remain explicit.

M10 remains **In progress**. Required gates include independently labeled Windows
and macOS stacks, broader configurations/intermediary coverage, scoped native
coverage, cross-family held-out accuracy/uncertainty, agreed performance goals,
and exact reviewed-revision execution on supported Linux/macOS/Windows profiles.
Hosted loopback runs do not close routed/shared-link gates. Compilation, skips,
and typed refusals do not establish native parity.

Keep [evidence semantics](../scanner-evidence.md),
[data review](../scanner-data-policy.md), and
[consumer compatibility](../consumer-compatibility.md) synchronized. Refreshing
signatures requires a new independent frozen hold-out before tuning. Automatic
scan integration remains deferred.
