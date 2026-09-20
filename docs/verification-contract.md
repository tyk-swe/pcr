# Reproducible forwarding verdicts

`verify-forwarding` compares selected physical observations. A result is a claim
about the declared decoder view, rules, and captures—not a diagnosis of a device.

## Identity is not the property under test

Choose a stable, unique identity independently of the field you intend to test.
For controlled fixtures, an explicitly assigned `ipv4.identification` can be a
case identifier; it is not assumed unique in arbitrary real traffic. Repeated
identities remain ambiguous. Payload identity cannot demonstrate a changed
payload on a matched pair: the changed observation has a different identity.

The report labels identity-only rules `correspondence_only` and emits
`verify.correspondence_only`. Overlapping identity/preservation fields emit
`verify.identity_preservation_overlap`. These are explanations, not automatic
rule rewrites.

`raw.bytes` is a registered projection for the undecoded raw layer used by the
UDP fixtures. It is **not** a universal UDP-payload alias. Decode bindings can
replace that raw layer. `udp.payload` is not registered in this source.

## Evidence states and checks

Each check reports `actual_state` and `expected_state` (the latter is null for
an egress-only expectation). States are `observed`, `absent`, `truncated`,
`decode_incomplete`, and `field_budget`.

Ordinary `--preserve FIELD` requires readable values on both sides. Two missing
values are unevaluable, not equal evidence. `--expect FIELD=VALUE` likewise
requires a readable egress value.

`--preserve-presence FIELD` explicitly compares presence in the declared decoder
view. `--expect-absent FIELD` asserts absence in that view on egress. They require
observed/absent states, not a truncated or diagnostically incomplete projection.
They do not establish the absence of an unknown or unsupported wire protocol.

Readable fixed-size decoded fields may establish a contradiction even when
unrelated payload bytes are missing. Variable-size values and repeated/list
projections may be prefixes, so incomplete captures do not establish their
preservation. An unqualified layer path can have unread occurrences even when
only one scalar was decoded. When decoding has diagnostics, use an explicit
occurrence such as `ethernet#1.source` or `vlan#1.vlan_id` to retain readable
fixed-size evidence from that header; unqualified values remain unevaluable.
A later projection-budget failure does not erase an earlier successful field
projection. Capture-level incompleteness still prevents pass.

The current implementation trusts the decoder's fixed-size scalar values. It
does not carry byte-range proofs for individual fields. Presence is a decoder
contract, not a protocol-recognition guarantee.

A fail requires an attributable violation. Missing counterparts, ambiguous
identity, incomplete evidence, or no matches without a demonstrated violation
are inconclusive. An identity-only pass is correspondence, not a property test.
An already demonstrated violation remains fail when other evidence is missing.

## Analysis and accounting

`analysis::Plan::physical(requirements)` skips unrequested TCP/UDP indexes and
retains IP reconstruction when either index is required. Forwarding derives
the plan from the compiled rules and each side's filter. Requested indexes
include reconstructed conversations before filtering, preserving capture-global
stream numbers. Selection and comparison use only physical-frame evidence.

Input frame, payload byte, encoded/decoded source-byte, and interface bounds
still count rejected input. Physical comparison continues to require usable
capture timestamps for evidence; missing times are not replaced with an epoch.

Collection, comparison scratch, retained detail, and publication are distinct
accounting domains. Defaults are 64 MiB collection evidence per input, 128 MiB
comparison scratch, 256 entries per detail category, and one shared 4 MiB detail
charge. The CLI permits at most 8 MiB of detail charges. The terminal record
remains bounded to 16 MiB; stream preflight reserves envelope headroom. Aggregate
JSON preflight counts the complete pretty-printed envelope and final newline
against the same ceiling before writing any success output.

Reducing detail counts/bytes never changes summary counters or verdict.
Omissions are explicit. Charges are deterministic conservative accounting,
not an allocator or RSS ceiling. Serialization, decoder state, and bounded
temporary values also consume memory. Do not fix an oversized report by
silently truncating its summary or by treating omitted detail as missing input.

## Time and publication

The synchronous CLI shares an invocation clock across capture preparation,
snapshots, analysis phases, comparison, and pre-publication checks. Pipeline
metadata reads and EOF checks use the same phase and invocation clocks.
A second analysis cannot restart the invocation allowance. Reader clocks are
restored when a pipeline returns or a callback unwinds.

Checks are cooperative. Blocking `Read`, native provider calls, filesystem
synchronization, and output writes cannot be forcibly preempted by a clock check.
Use a containing process with a hard deadline for an untrusted or potentially
blocking source. An artifact committed before a later reporting failure remains
committed; a deadline check before commit prevents a not-yet-published artifact.

## Library contract

Observations are opaque and bound to the exact compiled `Rules` instance and
capture side that produced them. Keep that instance alive and use it for both
collectors and verification. Recompiling identical text creates a different
rule identity and is rejected. This is misuse prevention, not cryptographic
attestation of a caller's input.

`verify` now returns `forwarding::Error`. Use `verify_with_limits` for explicit
`VerifyLimits` and an optional shared `Deadline`. `Declarations` groups value
and presence/absence rules. Total declaration count and source bytes are bounded.
Observation getters expose read-only evidence; hand-built observation literals
are no longer supported. Adding `plan` and `deadline` to `analysis::Options`
requires updating exhaustive struct literals.

## Reproduction bundle

Run the checked-in offline harness after building the portable CLI:

```sh
cargo build --locked -p packetcraftr-cli --no-default-features
python3 scripts/forwarding-regression.py \
  --binary target/debug/packetcraftr --large --output target/regression-example
```

The output directory must not already exist. The harness creates private files,
validates fixture framing/checksums, runs bounded children, and retains input and
output hashes, effective arguments, resource diagnostics, tool identity, expected
verdicts, observed verdicts, and test-contract results. Omitting `--binary`
generates fixtures with `execution=not_run`; it never claims an execution pass.

These are controlled offline fixtures, including intentional violations and
insufficient evidence. They are not captures of traffic through a device.
The harness tests that the declared expected result is obtained. In a real
regression requiring an observation, an inconclusive comparator result can fail
that test contract without claiming a device dropped a packet.

CLI source hashes cover the encoded bytes actually consumed through successful
EOF, including compressed input. A filename alone does not identify evidence.
The bundle preserves acquisition unknowns as null; it does not invent drop
statistics, offload settings, synchronized clocks, or a wire capture point.
Review capture location, offloading, native drop-counter semantics, decode-as
rules, and the observation window before making a device-level interpretation.
Treat captures and bundles as potentially sensitive data.
