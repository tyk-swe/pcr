# Implementation and adversarial review

## Delivery status

The source, tests, schemas, tooling, and documentation below were validated
locally on Linux with the pinned Rust 1.98.1 toolchain. The completed checks
include the full workspace test suite, fuzz-target compilation, detached consumer
and decoder-oracle checks, an executed offline forwarding regression, and the
release workflow's archive packaging step with a portable debug binary.

Privileged isolated native checks, Windows/macOS runtime checks, sustained fuzz
campaigns, and benchmarks were not run. Native-smoke parser tests use saved JSON,
not a native backend. Fixture generation without a PacketcraftR binary remains
explicitly `execution: not_run`.

## Recommendation coverage

| Recommendation | Implementation |
| --- | --- |
| Missing is not equal to observed | Per-cell `ValueState`, explicit `--preserve-presence` / `--expect-absent`, value checks requiring observed operands, and mutation regressions. |
| Check-specific completeness | A later projection-budget failure does not erase an earlier readable field; fixed-size header contradictions survive unrelated truncation. Capture-level incompleteness still prevents pass. |
| Bind observations to their rules | Private observation internals, exact compiled-rule instance identity, side/order/shape validation, typed contract errors, and public read-only accessors. |
| Demand-driven analysis | `analysis::Plan` disables unrequested IP reconstruction and TCP/UDP indexes for physical forwarding comparison. Required indexes retain global-before-selection semantics. |
| Composable resource accounting | Separate observation, scratch, detail-entry, and shared detail-byte budgets; typed scratch failure; omission counters independent of verdict; publication-size guard. |
| One invocation duration | Parent deadlines cross input preparation, repeated analyses, comparison, and publication. Reader metadata/EOF boundaries check the clock; RAII restores reader clocks after errors or panic. Commands without an invocation-duration flag retain their existing policies. |
| Property-oriented fuzzing | Five additional targets cover compression-to-analysis, transform/selection fidelity, forwarding semantics/detail invariance, HTTP segmentation, and arbitrary capture-to-HTTP composition. Existing targets remain. |
| Earlier independent evidence | Compact decoder oracle runs on pull requests; isolated native review is explicit, manually authorized, and bound to an immutable commit. Existing release gates remain. |
| Downstream contracts | v6 semantic schema, unchanged v5 schema, frozen external fixtures, bounded reference consumer, actual Rust serializer tests, external public-API consumer project, and archive verification requirements. |
| Usable resource policies | `ci-v1` / `workstation-v1` offline presets, explicit override precedence, resolved resource-source/stage metadata, disabled-stage reporting, and schema coverage. |
| External onboarding | Task-oriented entry points, revision-pinned Git dependency example, explicit unpublished-crate policy, migration and compatibility documentation. |
| Reproducible regression testing | Private offline evidence bundles with independent fixture construction, mutation cases, expected-versus-observed verdicts, input/output/tool hashes, effective arguments and resource diagnostics. Test-contract failure is separate from device-loss attribution. |
| Native capability honesty | A documented capability matrix plus an operator-authorized passive capture smoke tool. Unknown settings and unexercised cancellation remain explicit. |
| Measurement expansion | Existing measurement harness extended to HTTP/provenance and forwarding with/without retained details; no unmeasured capacity or timing claims. |

## Adversarial findings and refinements

### Optional-value equality was not proof of a property

Two absent TCP fields on UDP packets must not satisfy ordinary TCP-value
preservation. The new state model makes those checks unevaluable. An explicit
absence assertion instead has a narrowly documented decoder-view meaning.
Tests mutate both operands, evidence states, field presence, and result counters.

A single observation-wide incomplete flag was also too coarse: an unrelated
large payload projection could suppress a real header contradiction. Independent
compiled columns share the field budget but retain already-established values.

### Independently collected observations could omit requested checks

The old public shape permitted observations produced under one rule set to be
verified under another. Length-truncating iteration could then silently skip
new expectations. The patch rejects different compiled-rule identities, wrong
capture sides, non-increasing frame numbers, and shape mismatches before
comparison. The reference consumer separately checks the expected total number
of preservation and egress-expectation outcomes.

Equivalent rule text compiled twice intentionally does not constitute the same
instance. These in-process checks prevent accidental API misuse; they are not
cryptographic authentication of externally supplied evidence.

### Unrequested stages could consume required resources

Physical forwarding comparison previously inherited IP reconstruction and flow
indexing whether or not the query needed them. The new plan is conservative:
indexes requested by filters still see all physical input, and rejected frames
still consume the physical input budgets. It does not push arbitrary filters
upstream or change requested stream numbering.

### Permitted evidence could exceed a terminal record

Entry counts alone did not compose with byte-valued JSON identities. Retained
detail now has one byte charge across categories as well as per-list counts.
The compact report remains bounded and the verdict/census is independent of
detail retention. Counting serialization does not build another JSON buffer.

The single-terminal-record protocol is retained rather than adding a second
stream protocol. Arbitrarily increasing the terminal limit was not used as a
substitute for fixing accounting. A final report preflight is still necessary.

### Phase-local clocks left boundary gaps

The shared parent prevents starting a second input analysis with a fresh
invocation allowance. Reader checks cover metadata-only stretches and EOF,
and snapshot/publication boundaries check the same invocation. A scope guard
restores a pre-existing reader clock even if a user callback unwinds.

The review also found that stats had been omitted from the command-duration
dispatch, despite having a processing-duration argument. It is now included.
Processing and capture-reader deadline expiration now share the machine error
code `policy.duration_limit`; deterministic tests cover both paths.
A capture acquisition timeout is not reinterpreted as an overall publication
timeout: natural end-of-window capture completion must still be publishable.

### Tooling could overstate validation

Fixture-only harness runs explicitly produce `not_run`, never pass. A missing
binary leaves a failed manifest with all unexecuted cases still marked not run.
Child execution is shell-free, timed, output-spooled, and cleaned up on failure;
the final elapsed-time check also catches a child exiting between polls.

Passive native smoke evidence requires actual booleans for readiness, metadata
validity, and shutdown. Duplicate JSON keys, unknown schemas, broken sequences,
incomplete terminals, and repeated terminals are rejected. Idle cancellation
is not claimed from an arbitrary sleep followed by a process signal.

### New diagnostics initially lacked schema entries

Adversarial integration review found that the preset source labels and new
comparison/observation resource stages were not admitted by the copied schema.
The v6 enum definitions now cover these values (including existing preparation
and capture-storage stages). A preset resource fixture validates against v6,
and new Rust process tests exercise actual preset/override diagnostics.

### Earlier reproduction assumptions were wrong

The earlier review's `udp.payload` projection does **not** exist in this source.
Those earlier predicted examples would fail rule compilation as written.
The implemented fixtures use `raw.bytes` with ports whose payload remains Raw.
This is not a universal UDP-payload alias: decode-as or a recognized application
protocol can replace that decoder view. The previous reproduction package was
not used as evidence of a PacketcraftR runtime failure.

## Assumptions and residual risks

**Decoded scalar trust.** Fixed-size decoded scalar fields can remain observed
despite an unrelated diagnostic or truncated payload; variable-length and list
values are conservative. This relies on the registered decoder exposing scalars
only after the relevant header was available. The patch does not add a universal
byte-range proof system for custom decoders. Applications needing stronger
claims must constrain or independently validate their decoder registry.

**Absence scope.** `absent` means no projected field in the complete,
diagnostic-free declared decoder view. It is not proof that an unknown protocol
or header is absent from the wire.

**Hash scope.** CLI forwarding hashes the encoded stream actually consumed through
successful EOF, including container/compression bytes. A digest identifies those
bytes; it does not attest their acquisition, make a concurrently modified file
an atomic snapshot, or prove complete network capture. Library-created reports
may omit acquisition metadata and hashes. The bundle rechecks its fixture and
tool files and preserves unknown capture/drop/offload conditions as unknown.

**Cooperative time.** Blocking reads, provider calls, serialization, sorting,
filesystem operations, and writes cannot be universally preempted by these
clocks. The clocks provide cooperative checkpoints, not a hard process deadline.
The synchronous CLI's thread-local scope is not automatically inherited by new
threads; library users must explicitly pass the deadline. Already committed
files are not rolled back because later output fails.

**Memory accounting.** Charges include serialized values and documented structural
allowances, not every allocator overhead or process allocation. Transient
per-observation/check materialization remains. Presets are finite policy choices,
not benchmark-established capacities or RSS guarantees. The subprocess harness's
spool polling can overshoot between polls; use an OS/filesystem quota for a hard
disk limit. Windows termination does not constitute a job-object tree guarantee.

**Matching and causality.** Stable identity must be independent of the property
under test where possible. Identity-preservation overlap is warned about, not
magically disambiguated. Missing counterparts remain inconclusive in passive
comparison. A failed controlled test contract does not establish device loss.

**Schema/API migration.** v6 is intentionally incompatible with consumers that
assume v5 preservation semantics. Public observation construction and verification
errors also change. The prior v5 schema is retained unchanged, not silently
redefined. The reference consumer validates its interpreted subset, not the
entire schema or a second implementation of the filter language.

**Native administration.** Repository environment reviewers and required checks
must be configured by an administrator. YAML does not install those protections.
A manually dispatched run must be matched to the reviewed SHA; its GitHub run
association alone is not proof of a pull-request required-check result. No native
Windows/macOS execution, driver provisioning, or full cross-platform idle
cancellation certification was performed here.

**Workflow scope.** The new flagship harness is an offline regression workflow.
It does not yet drive an arbitrary active device-under-test lab from construction
through synchronized ingress/egress acquisition. Existing isolated Linux tests
and the passive capture smoke remain separate acquisition/runtime lanes. A new
general-purpose scenario language, GUI, broad protocol expansion, crate split,
or async rewrite was deliberately not introduced.

## Executed validation

| Check | Result |
| --- | --- |
| Workspace, fuzz, and standalone consumer formatting | Passed |
| Workspace Clippy, all targets and features, warnings denied | Passed |
| Workspace tests, all features, including doctests | 1,527 passed; 14 intentionally ignored (8 measurement fixtures, 6 isolated native tests) |
| Four-crate architecture validator | Passed |
| Detached public-API consumer | 1 test passed with an independently resolved lockfile and native defaults disabled |
| Fuzz compilation, pinned nightly 2026-08-28, warnings denied | All 15 targets passed; no fuzz campaign run |
| Compact decoder oracle, TShark 4.6.4 | 2 captures, 17 frames, zero mismatches |
| Portable CLI build | Passed with default features disabled |
| Large offline forwarding regression | All 9 scenario contracts passed, including expected fail and inconclusive verdicts |
| Independent forwarding consumer | 13 tests passed |
| Regression generator/runner | 8 tests passed |
| Native-smoke evidence parser (offline only) | 5 tests passed |
| Existing validation-evidence suite | 30 tests passed |
| Archive-verifier fixture suite | 7 passed; 1 optional real-binary test skipped |
| Release workflow package/extract/verify step | Passed separately with the portable debug binary, including the consumer and frozen fixtures |
| Current output fixtures | 130 validated against v6 |
| Schema retention | v5 byte-identical to baseline |
| Whitespace | `git diff --check` passed |

## Reproducing toolchain and offline validation

Use the repository-pinned toolchains and existing CI profiles. The regression
bundle directory must be new. Representative commands from the completed checks:

```sh
cargo fmt --all -- --check
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
rustfmt --check --edition 2024 examples/consumers/rust/composition.rs
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features --no-fail-fast
python3 scripts/check-architecture.py
python3 scripts/check-external-consumer.py
RUSTFLAGS='-D warnings' cargo +nightly-2026-08-28 check --locked --manifest-path fuzz/Cargo.toml --bins
python3 scripts/test-validation-evidence.py
python3 scripts/test-output-consumer.py
python3 scripts/test-forwarding-regression.py
python3 scripts/test-native-capture.py
python3 scripts/test-verify-archive.py
cargo build --locked -p packetcraftr-cli --no-default-features
python3 scripts/forwarding-regression.py --binary target/debug/packetcraftr --large --output target/pr-forwarding-regression
python3 scripts/check-decode-oracle.py --binary target/debug/packetcraftr --report target/decode-oracle.json
```

The release packaging smoke executed the Python step from
`.github/workflows/release.yml` in a temporary checkout using the portable debug
binary and locally generated build metadata. It did not produce a release build.
The isolated native contracts still require their explicitly authorized runtime
lane; sustained fuzz campaigns and measurements remain separate validation work.
