# Reproducible forwarding verdicts

`verify-forwarding` compares selected physical observations under declared
rules/decoder views; it does not diagnose a device.

## Identity is not the property under test

Choose a stable unique identity independent of the tested field. Assigned
ipv4.identification can identify controlled cases, not arbitrary traffic;
repeats remain ambiguous. Payload identity cannot match a changed payload.
Identity-only rules are correspondence_only with verify.correspondence_only;
overlap with preservation emits verify.identity_preservation_overlap. Neither
rewrites rules. raw.bytes projects the undecoded raw layer, not universal UDP
payload; decode bindings can replace it. udp.payload is not registered.

## Evidence states and checks

Checks report actual_state/expected_state: observed, absent, truncated,
decode_incomplete, field_budget; expectation ingress is null, not absent.
Ordinary preserve/expect requires readable values. Missing on both sides is
unevaluable, never equal. Preserve-presence/expect-absent explicitly compare
decoder-view presence with observed/absent states, not unknown wire protocols.

Fixed-size readable scalars can contradict despite unrelated missing payload;
variable/list values may be prefixes and cannot prove preservation. With diagnostics,
explicit occurrences (ethernet#1.source, vlan#1.vlan_id) can retain scalar evidence
while unqualified paths remain unevaluable. Later projection failure does not
erase earlier successful projection; capture incompleteness still prevents pass.
The decoder is trusted here; fields carry no individual byte-range proof.

Fail requires an attributable violation, which remains fail despite other missing
evidence. Missing counterparts, ambiguity, incompleteness, or no matches without
a violation are inconclusive. Identity-only pass proves correspondence only.

## Analysis and accounting

`analysis::Plan::physical(requirements)` skips unrequested transport indexes;
requested indexes use capture-global reconstruction before filtering. Comparison
is physical-frame only; frame/payload/source/interface bounds count rejected input.
Evidence needs usable capture timestamps, never an invented epoch.

Collection, scratch, retained detail, and publication are separate:
max-evidence-bytes, max-scratch-bytes, max-details, max-detail-bytes.
Detail charges leave terminal headroom. A terminal record is ≤16 MiB including
newline; aggregate JSON preflight counts the full pretty envelope before success
output. Detail omission never changes counters/verdict. Conservative logical
charges are not RSS; decoder/transient/serializer work also consumes memory.
Never silently truncate the summary or treat omitted detail as missing input.

## Time and publication

One invocation clock spans preparation, snapshots, analysis, metadata/EOF,
comparison, and publication. A second capture cannot restart it; reader clocks
are restored on return/unwind. Blocking `Read`/providers/filesystem/output are
cooperative; use process containment for hard deadlines.
Commit checks prevent unpublished artifacts after expiry; already committed
artifacts remain committed if later reporting fails.

## Library contract

Opaque observations belong to the exact compiled `Rules` instance and capture side.
Keep it for both collectors/verification; recompiling identical text creates a
new identity and fails. This is misuse prevention, not cryptographic attestation.
Getters are read-only; observations cannot be constructed manually.
`verify_with_limits` takes explicit `forwarding::Limits` and an optional shared `Deadline`.
`Declarations` bounds total rules/source bytes and groups value/presence checks.

## Reproduction bundle

```sh
cargo build --locked -p packetcraftr-cli --no-default-features
python3 scripts/forwarding-regression.py --binary target/debug/packetcraftr \
  --large --output target/regression-example
```

The destination must not exist. The harness creates private files, checks framing/
checksums, bounds children, and retains hashes, effective arguments, diagnostics,
tool identity, expected/observed verdicts, and test-contract results. Without
`--binary`, `execution=not_run`, never a pass. Intentional violations/inconclusive
fixtures test comparator behavior, not traffic through a device.

Source hashes cover encoded bytes consumed through EOF, including compression.
Acquisition unknowns remain null. Review capture point, offload/drop-counter
semantics, decode-as rules, and window before device interpretation; no automatic
loss/synchronized-clock claim follows. Treat bundles as sensitive.
