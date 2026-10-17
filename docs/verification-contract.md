# Reproducible forwarding verdicts

`analyze verify-forwarding` compares selected physical observations under declared
rules and decoder views; it does not attribute causes to a device.

## Identity is not the property under test

Choose a stable unique identity independent of the tested field. `ipv4.identification`
suits controlled cases, not arbitrary traffic; repeats remain ambiguous, and a
modified field cannot serve as identity. Identity-only rules report
`correspondence_only` (`verify.correspondence_only`); overlap with preservation
emits `verify.identity_preservation_overlap`. `raw.bytes` projects the undecoded
`raw` layer (not universal UDP payload, as `udp.payload` is not registered).

## Evidence states and checks

Checks report `actual_state`/`expected_state`: `observed`, `absent`, `truncated`,
`decode_incomplete`, or `field_budget` (expectation ingress is `null`). Ordinary
`--preserve`/`--expect` require readable values; missing on both sides is
unevaluable, never equal. `--preserve-presence` and `--expect-absent` compare
decoder-view presence explicitly.

Fixed-size readable scalars can contradict despite unrelated truncation; variable
or list values may be prefixes and cannot prove preservation. `fail` requires an
attributable violation and takes precedence over missing evidence. Without an
attributable violation, missing counterparts, ambiguity, incompleteness, or empty
selections produce `inconclusive`.

## Analysis, accounting, and time

`analysis::Plan::physical(requirements)` reconstructs requested transport indexes
capture-globally before filtering; comparison is physical-frame only and requires
usable capture timestamps. Collection, scratch, retained detail, and publication
have separate bounds (`--max-evidence-bytes`, `--max-scratch-bytes`,
`--max-details`, `--max-detail-bytes` ≤ 8 MiB, leaving headroom for the 16 MiB
terminal ceiling). Detail omission never changes counters or the verdict.

One invocation clock spans both captures, comparison, and publication. Opaque
library `Observation` values bind to the exact compiled `Rules` instance and
capture side; pass them to `verify` or `verify_with_limits`.

## Public behavior checks

The retained CLI `forwarding_verification_contracts` integration module exercises
forwarding verdicts with generated local captures. Run it with:

```sh
cargo test --locked -p packetcraftr-cli --no-default-features --test integration forwarding_verification_contracts
```
