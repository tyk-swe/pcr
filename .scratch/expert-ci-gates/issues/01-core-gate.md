# GATE-01: Evaluate expert findings against explicit CI criteria

Status: resolved (e10438c4; all listed tests green)
Blocked by: BASE-01
Size: small
Spec: [gate domain, truth table, API, EG02–EG05](../spec.md)

## What to build

1. Add `analysis::expert::gate::{Options, Gate, Report, Verdict, Reason, Error}`
   with the exact API/semantics in the spec. Keep state constant-sized and
   counters checked; preserve neutral library ownership of classifications.
2. Implement the severity comparison and priority-ordered truth table.
   Evaluation consumes the gate and takes the completed matched-frame count;
   it does not own or rerun an analysis session.
3. Add public `expert_gate_contracts.rs` covering thresholds, allowance and
   coverage boundaries, simultaneous violations, and order-independent counting.
   Exercise invalid minimum through the public constructor. Use owner unit
   support for unreachable counter-overflow construction if needed.

## Acceptance and validation

- [x] EG02–EG05 hold, including inclusive threshold/equality behavior.
- [x] All report fields equal configured options/observed counts.
- [x] No finding lists or code maps grow gate memory.
- [x] Existing expert collector/selector/summary behavior is unchanged.
- [x] Public errors are typed, classified, and preserve relevant sources.

```sh
cargo test --locked -p packetcraftr-core --test expert_gate_contracts --test pipeline_expert_contracts --test expert_transition_contracts
```

## Comments

Process exit values and machine enum conversions belong to GATE-02, not core.
