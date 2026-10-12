# M12: TCP diagnostic scans

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M6](m06-port-planning-inference.md) | ACK/window and flag-dependent diagnostics |

The scan engine currently sends SYN; arbitrary packets built elsewhere are not
a diagnostic scan workflow. No new TCP mode is implemented here.

## Intended behavior

- Add ACK/window and FIN/NULL/Xmas/Maimon families with bounded mode-specific
  construction, correlation, retries, and retained evidence.
- Select/publish probe flags separately from the inference rule. A custom flag
  combination must not silently adopt the wrong base-method semantics.
- Keep all attempt observations and operational failures beside inferred states.
  ACK responsiveness is not an open-port finding; `unfiltered` is a method claim.
  Silence and stack-dependent responses can remain ambiguous.
- Reuse policy, endpoint identity, pacing, duration, packet/byte, preparation,
  and evidence ceilings. Unsupported paths fail explicitly, without hidden fallback.

## Decisions before implementation

Define the minimal modes, exact correlation/state tables, supported custom-flag
policy, platform capability requirements, and publication vocabulary. Document
which conclusions rely on stack behavior and which distinguish filtering from
reachability. Preserve mainstream SYN/connect inference.

## Acceptance gates

Use independently expected IPv4/IPv6 responsive, silent, blocked, contradictory,
malformed, unrelated, late, and reordered fixtures for every mode. Assert flags,
rule identity, uncertainty, partial failures, finite limits, and final wire checks.
Retain exact-revision native acceptance on supported profiles under
[M2](m02-ground-truth-benchmarks.md)/[M3](m03-native-validation.md).

Synchronize [evidence](../scanner-evidence.md), contracts, examples, migration,
and data review as needed. Idle/bounce/evasion remain outside scope. M12 stays
**Planned**, with no runtime or parity claim.
