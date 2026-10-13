# Consumer compatibility policy

## Versioning and immutable evidence

A contract family covers names, units, meanings, enums, ordering, and terminal
semantics, not only JSON shape. Incompatible changes require a new family even
if an old schema accepts their shape.

Archives freeze schema snapshots/checksums. Resolve `$id` to the bundled local
file, never moving `main` or a network fetch; do not alter published archives.
Current producers emit [output/v15](../schemas/packetcraftr.output.v15.schema.json)
and [packet/v2](../schemas/packetcraftr.packet.v2.schema.json). Beta.3 used output/v2
and packet/v1; output v6–v14 remain frozen. Tolerate unknown object members, but
never guess unknown families, verdicts, check kinds, or evidence states.
Examples are fixtures; CLI conformance tests validate actual serializers.

## Fields, omission, and identifiers

Counts/bytes are nonnegative integers, not booleans. Durations use documented
units; second/nanosecond timestamps imply no clock synchronization. Frame references
are one-based/capture-local, envelope sequences zero-based/output-local, and
conversation numbers capture-global before selection.

Missing metadata, null ingress operand on an expectation, and explicit decoder
`absent` are distinct. A missing source hash is not verified identity. Summary
counters include accepted evidence regardless of retained detail/omissions.
Forwarding fail/inconclusive returns exit 1 after publication; an error envelope
is execution failure. Neither exit status nor a partial list alone is a verdict.

## Output family v15

V15 adds TCP diagnostic scans. Raw scans with TCP scan endpoints publish the
effective `plan.tcp_scan` `{mode, flags}`; each raw scan-stage TCP probe and
`probe_sent` record carries the same object. Discovery TCP probes always carry
`{mode: syn, flags: 2}`, independent of the scan plan. A correlated direct TCP
response (not an ICMP error or silence) carries its
advertised `tcp_window` (0..=65535, as observed; never an identity). Packet-free
`--list` publishes `ports.tcp_scan` when a TCP endpoint is listed. Connect and
non-TCP records omit them. Modes are `syn`, `ack`, `window`, `fin`, `null`, `xmas`,
`maimon`, and `custom`; flags must equal the mode's fixed value, except custom
(0..=511). The inference `state` gains `unfiltered` and the `rule` vocabulary
gains `tcp_ack.*`, `tcp_window.*` (`reset_nonzero`, `reset_zero`), `tcp_fin.*`,
`tcp_null.*`, `tcp_xmas.*`, `tcp_maimon.*` (each `reset`, `icmp_unreachable`,
`time_exceeded`, `unclassified_reply`, `silence`), and `tcp_custom.reply`/`silence`.
The schema ties each rule to its state and to the probes' mode.

Meanings differ from v14: `unfiltered` (an ACK reset) never means open; window
`open`/`closed` and FIN-family `open_or_filtered`/`closed` are stack-dependent
heuristics; custom infers `unknown` regardless of its flags. Direct TCP
responses to diagnostic probes are attempt-classified `unknown` or (FIN-family
reset) `closed`, never `open`; ICMP errors keep their own classification, with
port-unreachable `unreachable`. Consumers must not treat an inferred state as
authenticated identity or reliable port detection. See [TCP diagnostics](tcp-diagnostics.md).

V14 and earlier families remain immutable; consumers must explicitly adopt v15.

## Output family v14

V14 adds standalone `identify-os`. Aggregate results and `os_preparation`,
`os_probe`, `os_additional`, `os_undecoded`, `diagnostic`, and `complete` stream
records separate exact evidence, suitability, observations, and qualified
family candidates. Outcomes are `matched`, `ambiguous`, `unknown`, or
`inconclusive`; competing families remain ambiguous. `qualified` confidence is
ordinal, never a probability or authenticated identity.

Candidate provenance names the corpus/version, signature, reference, and
supporting observation indices. The independently versioned
`packetcraftr.os-fingerprints/v1` document names `packetcraftr.os-probes/v1`.
Unknown or missing evidence does not qualify a signature. `complete` concerns
execution and retained evidence; an unsuitable target can complete with an
inconclusive identification. Expiry/cancellation follows existing typed-error
and stream terminal semantics. See [OS identification](os-identification.md).

V13 and earlier families remain immutable; consumers must explicitly adopt v14.

## Output family v13

Frozen v13 preserves v12 and adds explicit TLS, SMTP/FTP fields, `tls_failed`,
`usage.tls`, and supported candidate metadata. TLS failure retains evidence,
never cleartext fallback. Passive TLS fingerprints keep their analysis meaning.

Probe `tls` includes declared `server_name` (null without SNI),
`handshake_complete`, negotiated protocol/cipher, ordered DER `certificates_hex`,
truncation, encrypted lifetime read/write bytes/steps, and always
`unauthenticated: true`. A handshake or certificate authenticates no host/name.
Application request/response hex and counters describe plaintext: accepted writes
are charged even if flush fails; encrypted counters measure completed socket work.

`usage.tls` separately charges encrypted bytes, retained certificate bytes, and
steps, including failed handshakes; cleartext usage is zero. Optional candidate
hostname/device/CPE values have `observed_field` field/index or `match_rule`
provenance tied to corpus/version/probe/rule. Unsupported values are absent;
static CPE versions are wildcarded and assert no vulnerability.

## Output family v12

Frozen v12 introduced explicit `identify`, never automatic scan identification.
JSON `records` and NDJSON `identify_endpoint` records keep excluded/unknown/
matched/ambiguous/malformed/truncated/budget_exhausted outcomes, exact request/
response hex, numeric peers, I/O outcome, observed unauthenticated claims, and
separate candidates. Candidates cite corpus/version/probe/rule/field indices.
Ordinal `claim` is weaker than `protocol`, never a probability. Protocol matches
supply no product version; unknown/ambiguous/malformed/truncated results supply
no exact versions. No identification result is a vulnerability finding.

The terminal contains endpoint count, data versions, usage, elapsed time, and
complete/cancelled state. Budget exhaustion preserves evidence with `complete=false`.
Operation timeout excludes preparation/publication; keep overall max-duration
larger to allow publication. Overall expiry/cancellation yields a typed error
when writable; unwritable output has no terminal guarantee.

## Output family v11

Frozen v11 introduced optional raw-scan `traceroute`, host-order results,
traceroute_probe/undecoded/host events, and terminal plan/retention metadata.
The plan declares hop/attempt/probe limits, fallback strategy, and optional reuse age.

Host status is complete/incomplete/not_traced; completion is reached/unreachable
or maximum_hops/timeout respectively. Not-traced reasons are no_responsive_probe
or scoped_target, without completion/selection. Observed selection cites the scan
probe's stage/sequence/reply/time; requested selection uses explicit fallback.
Fresh `hops` are observations. `reused_hops` cite source host/probes/responders/
time/age and are claims, with no new probe record. Host stream records follow
their probes and list sent sequences instead of aggregate hops. Standalone trace
keeps its shapes. See [trace semantics](scanner-evidence.md#traceroute-stage).

## Output family v10

Frozen v10 introduced required `scheduling` on scan/connect results and terminals:
fixed/adaptive mode, effective config, observed_peak_window, retries_started,
conditions, incomplete hosts, and connect operation/process ceilings.
Peak pending count is not throughput. Adaptive `scan: incomplete` includes host
deadline exhaustion and admitted workers never calling providers.
Suspected rate limits cite responder, counts, and control/loss sequences; loss
or filtering remain alternatives and classifications never change.

## Output family v9

Frozen v9 introduced required hosts, discovery plan, and discovery/scan stages
on probes/sends/failures. Host discovery is not_requested/skipped/responded/
no_response; scan is scanned/skipped/not_requested (v10 adds incomplete).
Silence is uncertain; omitted/skipped work implies no reachability.

Reasons carry wire/socket/cache evidence and direct/cached/possible_proxy basis.
Proxy suspicion is shared link evidence, not cause. Neighbor resolved/silent/
routed/not_applicable records selected interface; a cached gateway next_hop is
not target identity. PTR names are unauthenticated observations.
Endpoints/counts cover scan only. See [host semantics](scanner-evidence.md#host-observations).

## Output family v8

Frozen v8 introduced required scan/connect plans with requested/selected method,
automatic-choice reason, catalog version, exclusion count, and curated UDP
applied/overridden ports. Port hints are not identification.
Inference publishes optional state, rule, and a complete disjoint partition of
attempt sequences: supporting/conflicting/unanswered/failed. Operational-only
failures imply no state; attempt classifications retain older meanings.
Late/duplicate/ambiguous raw frames stay unattributed. Endpoint stream records
cite aggregated probe sequences; target_list may include selected ports.
[Inference](scanner-evidence.md#port-inference) defines comparison mappings.

## Output family v7

Frozen v7 introduced target_list (`method: target_list`, target events/terminal),
optional declared zone/resolved interface scope on scan evidence/failures, and
exact retained_evidence_bytes. Scope is identity, not another claim vocabulary.
Raw/trace retention charges wire bytes; connect charges structures/error strings,
not RSS. Historical families are never reused for new output.

## Streams and the reference consumer

NDJSON requires contiguous zero-based sequences, newline-ended records, and
exactly one complete/error terminal. EOF without terminal, gaps, duplicate JSON
keys, or post-terminal records fail. Record/stream bounds are separate.

```sh
set +e
packetcraftr --output ndjson verify-forwarding before.pcap after.pcap \
  --identity ipv4.identification --preserve ipv4.ttl > report.ndjson
status=$?
set -e
python3 examples/consumers/forwarding.py --format ndjson --exit-code "$status" < report.ndjson
```

The forwarding consumer accepts v6–v15 and validates its interpreted subset:
states, counter/omission relationships, requested checks, and verdict coherence.
It does not replace full JSON Schema validation. Its success means interpretation,
not forwarding pass; inspect execution/verdict or the harness's test contract.
Frozen consumer fixtures and real-serializer conformance remain separate checks.

## Rust API adoption

Crates are unpublished (`publish=false`). Public struct/enum changes can break
Rust callers despite compatible JSON. From a separate project, pin a full reviewed
commit and commit the consumer lockfile; the workspace lockfile does not govern
its resolution:

```toml
[dependencies]
packetcraftr-core = { git = "file:///path/to/checkout", rev = "FULL_COMMIT_SHA" }
```

Use a shared repository URL when collaborating, with the revision available there;
never substitute `main` for a pin. `scripts/check-external-consumer.py` creates an
independent workspace, resolves cached dependencies offline, and tests public
policy-gated injected-provider workflows without native features/internal helpers.
