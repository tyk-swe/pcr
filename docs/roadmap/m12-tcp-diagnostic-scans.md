# M12: TCP diagnostic scans

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M6][m6] | Firewall and stack diagnostics |

PacketcraftR's TCP scan sends SYN and nothing else: the scan workflow builds
and recognizes only SYN probes. Other flag combinations can be built and sent
with the packet tools, and that is not a scan, because nothing correlates the
replies or infers anything from them. Scans with other flags answer
different questions, such as whether a firewall is stateful, and their answers
depend on how the target's stack treats unusual segments.

This milestone adds those scan families as diagnostics for controlled firewall
and stack tests, on the plan and inference foundations of [M6][m6].

## Outcome

- ACK and window scans report whether a path filters, not whether a port is
  open.
- FIN, NULL, Xmas, and Maimon scans are available where they are useful for
  controlled tests, with their stack-dependent limits stated.
- The flags a probe carries and the rule used to interpret replies are chosen
  separately.

## Invariants

- ACK responsiveness does not imply an open port.
- Window and flag-dependent heuristics keep their stack-compatibility limits
  explicit in results.
- Ambiguous states remain ambiguous. Idle-scan-only semantics are not added
  merely to reproduce every Nmap label.
- These modes are diagnostics for authorized, controlled tests. Evasion is
  outside this roadmap.

## Scope

### M12.1 ACK and window scans

- An ACK scan that classifies each endpoint by whether a reset returned, an
  ICMP error returned, or nothing did.
- A window scan that additionally examines the reset's window field, with the
  dependence on the target's stack stated in the result.

### M12.2 FIN, NULL, Xmas, and Maimon scans

- Flag-based scan families, added where they are useful for controlled
  firewall and stack tests.
- Each family has its own correlation and inference rules, and documents the
  stacks known not to follow the behavior the inference assumes.

### M12.3 Probe flags and inference rules

- The configured probe flags are one input and the chosen inference rule is
  another. Neither implies the other.
- A result records both, so a reader can tell which rule produced a state from
  which probe.

## Decisions to settle

1. Which families ship (recommended: ACK and window first; each of FIN, NULL,
   Xmas, and Maimon only with a fixture that shows a diagnostic use and a
   stack-dependent counterexample).
2. How an inference rule is chosen for custom flags (recommended: the request
   names the rule; flags with no named rule publish attempt outcomes only).
3. The inferred-state labels these modes need (recommended: extend the
   [M6][m6-inference] vocabulary, treating each new label as a contract change
   under the [compatibility policy][compatibility]).
4. How a mode is selected (recommended: a typed method on the scan request,
   alongside the method planning in [M6][m6-method]).

## Exit criteria

- [ ] Each mode has an observable correlation and state matrix covering
      unrelated replies, valid negative replies, ICMP quotations, and silence.
- [ ] ACK responsiveness is never reported as an open port.
- [ ] Window and flag-dependent results state their stack-compatibility limits.
- [ ] Ambiguous states remain ambiguous, and no idle-scan-only semantics are
      added.
- [ ] Known implementation-dependent counterexamples are acceptance fixtures.
- [ ] Applicable IPv4, IPv6, Linux, macOS, and Windows native checks pass
      before a mode is marked complete.
- [ ] Unsupported execution paths publish capability failures, not port
      classifications.

[m6]: m06-port-planning-inference.md
[m6-inference]: m06-port-planning-inference.md#m65-inferred-states-and-reasons
[m6-method]: m06-port-planning-inference.md#m66-capability-aware-method-planning
[compatibility]: ../consumer-compatibility.md
