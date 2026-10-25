# Testing policy

Every test must name a project behavior and fail for a plausible defect in that behavior. Assertions about private counters, allocation layouts, incidental dependency defaults, current time, installed software versions, or external services do not establish a project contract. Check returned packets, decoded fields, events, diagnostics, exit status, or filesystem effects instead. Rejection alone is enough when rejecting the input is the complete contract.

Use controlled input and independently expected output. A round trip or agreement between two implementations is useful supplementary evidence, but neither alone rules out a shared defect. Protocol vectors must cite their specification and the date checked when an external fact is load-bearing. Read constants and fixtures that the project owns rather than pinning facts supplied by an installed dependency.

Workflow tests use injected providers and clocks. A synchronization test may use real threads when thread lifetime or admission is the behavior being tested. Coordinate entry and release explicitly and bound every wait. Mock calls only when the interaction is the contract, such as rejecting transmission before authorization. Test budget refusal while data is retained, then successful work after release, rather than inspecting bookkeeping fields.

Keep regressions in their existing owning test file. Inline Rust tests belong with their module and separate Rust tests belong in that module's `tests.rs`. Python uses `scripts/tests/test_<module>.py`. A new feature can have a new mapped file. Do not add per-ticket suites. Modified helpers must be typed and follow AGENTS.md, including its comment and suppression rules.

# Review checklist

A reviewer must be able to identify the protected behavior, a representative defect that would fail the assertion, the controlled inputs or synchronization, and why the test belongs in its chosen file. Check that an upstream release, the clock, or unrelated machine state cannot cause failure. Automated mutation checks supplement this review.

# Local checks

The normal Python runner remains unittest.

```sh
python3 -m unittest discover -s scripts/tests -v
python3 -O -m unittest discover -s scripts/tests -v
cargo test --locked --workspace --lib --all-features
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
```

CI also retains the portable, default, layer 2, layer 3, minimum Rust version, documentation, macOS and Windows checks. Use the narrow affected tests during repairs and the complete CI matrix before requesting review.

# Mutation checks

`.config/mutation.toml` pins cargo-mutants and Cosmic Ray and maps every Python production module, including repository tools, to its tests. `requirements-dev.txt` installs Cosmic Ray. Install cargo-mutants with the version in that file's companion TOML configuration.

Python mutation runs execute the suites declared for their module. Ordinary CI still discovers the entire unittest suite. Ownership for the mutation tools is split between score parsing in `test_mutation_results.py`, selection in `test_mutation_scope.py`, orchestration in `test_run_mutation.py` and SDK execution in `test_run_mutation_tools.py`. The orchestration cases also exercise the parser and selector. `test_mutation_test_runner.py` owns the test harness, and `test_mutation_reuse.py` owns seed validation and receiver coverage. These files replace the former combined `test_mutation.py` without dropping cases. The four other production modules retain their existing mapped suites.

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
cargo install cargo-mutants --version 27.1.0 --locked
python3 scripts/run_mutation.py select --full --plan mutation-plan.json
.venv/bin/python scripts/run_mutation.py run --plan mutation-plan.json --language python
python3 scripts/run_mutation.py check --plan mutation-plan.json --language python
python3 scripts/run_mutation.py run --plan mutation-plan.json --language rust --profile all
python3 scripts/run_mutation.py check --plan mutation-plan.json --language rust
```

For a PR, use `select --base BASE_SHA` instead of `--full`. Selection uses both sides of deleted or renamed files. Rust production edits select whole changed files. A separate or inline test change selects its whole crate. Crate dependency changes select all Rust crates. Python tests select their mapped modules. Shared test support selects every affected language module. Shared fixtures, workflow or mutation configuration, root dependencies and testing policy changes select both language suites. Unknown Python production modules fail selection until ownership is recorded.

The runner takes one snapshot of tracked and untracked, nonignored source before a run, then gives each target a disposable copy. It records the commit and a digest of that source snapshot. Review policy is copied but excluded from the source digest, because it identifies the source it reviews. Artifact directories must be ignored by Git or outside the checkout. Cargo-mutants runs workspace tests against every selected mutant, so dependent crates can detect errors. When a package has a `build.rs`, the disposable manifest exposes it as an additional binary target so cargo-mutants can discover it. The amended manifest is retained with the results. Rust shards are numbered from one at this script's interface and translated to cargo-mutants' zero-based numbering. No mutant is sampled or silently removed.

The Python harness is production tooling and receives its own mutation measurement. Each run first copies the harness into its artifact directory, so mutations to the measured harness cannot change the bootstrap that judges them. Interpreter and bootstrap paths are shell-quoted. The baseline session and its exported report are retained and checked for successful, nonempty unittest execution. The SDK's process exit status alone is insufficient evidence. This validation also applies when discovery finds no mutants.

Rust runs an explicit workspace baseline before mutation. The pinned SDK applies workspace selection to mutants but selects only mutated packages for its own baseline, so its successful baseline alone cannot establish that dependent-crate tests were already healthy. Every artifact also retains its complete normalized target, including language, group, files and selection reason. The gate rejects evidence for a different target, even under the same source revision.

The existing weekly CI schedule calls the full mutation workflow. PRs call the same workflow with scoped selection. Manual dispatch runs a full audit. Pushes to the default branch retain normal CI without repeating the full mutation audit. Rust runs on the existing Linux, ARM and Intel macOS, and Windows images with each supported feature profile. Each platform/profile context runs 64 shards with one mutation worker per job. Context calls are serialized and each context admits at most four shard jobs, preserving the four-job Rust limit. The gate requires every platform, profile and shard, then combines their outcomes per crate. A mutant is killed when any required run catches it. Code disabled in one profile can be tested by another. A timeout never creates a kill, and a mutant is compilation-invalid only if every run that discovered it fails compilation. Each Python module runs in a separate serial job, preserving one active Python worker while giving each module the runner's full time allowance. The gate still requires results for every module in the original selection. A score aggregated across modules or crates cannot make a weak group pass.

The Linux all-features context runs first and publishes a complete direct seed. Other contexts discover their own inventories and reuse only exact identities that this seed actually killed. Seed survivors, timeouts, compilation-invalid mutants and identities absent from the seed still execute. Each receiver starts a fresh cargo-mutants output directory containing only the verified prior kills. Iteration filtering occurs before sharding. Each context runs its own workspace baseline even when no executable mutants remain.

The seed is bound to the full source fingerprint, Git revision, tool version and requested target. The gate requires its actual completed Linux/all shard cohort and compares every outcome and evidence path. One receiver shard carries its complete inventory, reused identities and exact seed text; all shards carry the same coverage digest. The remaining inventory must be executed exactly once across that context's shards. The score combines actual outcomes only, without inventing receiver kills. Scores publish executed and reused counts by context and the seed provenance. Full weekly throughput remains unverified until a complete production matrix finishes.

The following example uses one shard for a local two-context run. CI uses the same commands with 64 shards and the full platform and feature matrix.

```sh
python3 scripts/run_mutation.py run --plan mutation-plan.json --language rust --profile all --platform-label ubuntu-24.04 --output mutation-results/rust/seed-run
python3 scripts/run_mutation.py seed --plan mutation-plan.json --language rust --output mutation-results/rust/seed-run
python3 scripts/run_mutation.py run --plan mutation-plan.json --language rust --profile portable --platform-label ubuntu-24.04 --seed mutation-results/rust/seed-run/seed --output mutation-results/rust/portable
python3 scripts/run_mutation.py check --plan mutation-plan.json --language rust --seed mutation-results/rust/seed-run/seed --platforms ubuntu-24.04 --profiles all portable --output mutation-results/rust
```

A group's score is killed mutants divided by eligible viable mutants and must be strictly greater than 90 percent. Timeouts remain in the denominator and never count as kills. Only compilation-invalid mutants and individually reviewed equivalent mutants are excluded. The checker requires a successful baseline, complete inventory, consistent shard metadata, actual test execution evidence, and results for every selected mutant. Missing reports, duplicate results, runner failures and unfinished runs fail the gate. Zero eligible mutants are reported as not applicable with the selection reason, including the invalid and equivalent counts.

Equivalent exclusions belong in `.config/mutation-exclusions.json`, one exact mutant per entry with `group`, `revision`, `identity`, and a nonempty `evidence` explanation. Set `revision` to the score artifact's `source_revision`, the source fingerprint rather than the Git commit. This lets the review be committed without referring to its own hash. Each entry applies only to that exact source and surviving mutant. Scores publish every applied entry and its evidence. The gate still requires the current Git commit and matching worktree source. Do not add broad patterns or exclusions merely to meet the score. Review every survivor even when the score passes.

Artifacts retain the selection plan, source revisions and digests, tool versions, raw tool reports, session databases, individual outcomes, diffs, logs, exclusions and per-group scores. Rust jobs also publish their normalized receipts separately, so the final gate can validate all results without downloading every verbose compiler log onto one runner. Raw reports and logs remain separate required artifacts. The gate recomputes the current worktree fingerprint, rejects reports from another commit, source snapshot or tool version, and never treats absent artifacts as success. CI stores downloaded reports and score output under ignored `mutation-results/` paths so they cannot become measured source. Python mutant identities include their source span and operator rather than a session-specific job identifier. For tool report semantics, see [cargo-mutants workspace testing](https://mutants.rs/workspaces.html), [its warning about test-only diffs](https://mutants.rs/in-diff.html), and [Cosmic Ray sessions](https://cosmic-ray.readthedocs.io/en/latest/tutorials/intro/index.html).

# Audit record

The initial inventory contained 282 Rust tests and 50 Python tests. The initial all-features Rust baseline and Python baseline passed. The Rust mutation inventory contained 26,453 candidates before repairs. These counts describe this audit's starting point and are not assertions in the test suite.

| Subsystem | Disposition and protected behavior |
| --- | --- |
| Message streams | Replaced private buffer counts with successful follow-on decoding under a small budget. Check complete message bytes and source frame identities. Retained SIP framing, gap, reset and unsupported-version cases. |
| Provenance | Replaced exact copy counts, tree comparisons and memory-layout charges with ordered independent source expectations, immutable published snapshots, budget refusal, shared-owner lifetime and admission after release. |
| Scan correlation | Removed comparison instrumentation and private map-layout assertions. Check direct and quoted reply ownership, retirement and reuse of admission. The retirement fixture constructs transport fields without assuming unregistered ports. |
| Packet preparation | Removed exact build-work instrumentation. Kept fresh-route, authorization, changed source and MTU checks. Replaced allocation-layout checks with bounded admission and independently decoded packet destinations, ports and payloads. |
| DNS security evidence | Replaced private grouping-map assertions with emitted finding suffix and distinct-label counts. |
| Security capture and indicators | Reviewed all 26 security tests. Beacon precision now runs timestamped SYN packets through analysis. Hunt normalization checks emitted matches, finalization checks independent finding content under a frozen clock, and successful indicator parsing is followed by expected matching behavior. HSTS, CSP and cookie protocol assertions cite dated sources. |
| Policy resolution | Injected a refusing resolver so denial tests detect provider calls without relying on external DNS. |
| CLI decode selectors | Replaced a success-only assertion with the actual selected UDP codec. |
| CLI ranges and stream selectors | Reviewed decimal syntax, one-based positions, frame selection, timestamp scaling and scan-selection cases. Added range/sampling intersection, endpoint bounds, malformed-range diagnostics and complete TCP/UDP stream identities. |
| Python JSON support | Reviewed all 23 helper cases. Replaced allocation measurements with preserved contents, exercised exact byte and nesting boundaries, validated nested siblings after empty containers, and checked file read budgets through a controlled source. Digest validation and atomic replacement permissions now have meaningful coverage. |
| Mutation enforcement | Added behavioral checks for strict score boundaries, weak groups, incomplete and duplicate results, timeouts, worker failures, shard coverage, deleted tests, shared inputs, source identity and disposable source snapshots. A real two-crate fixture verified that dependent-crate tests kill all five mutants. |
| Native workers and cleanup | Reviewed runtime, operation, sink, native worker, capture and all nine native registry cases. They now verify admission refusal during callbacks, TLS destruction, panic cleanup and capture shutdown, then successful replacement work after release. Registry tests check delivered replies and recovered capacity rather than private state. Published resource diagnostics remain covered. |
| CLI serialization | All cases are reviewed. Application, stream and followup cases verify complete flushed records, byte-budget refusal, terminal errors and worker admission after cancellation. Machine rendering checks real prefix bytes and completed diagnostics rather than write-call counters. Followup scans use injected providers that cannot access the host network. |
| Scan scheduling | Reviewed adaptive scheduling, connect classification and deadline-index cases. An independent timeline replaces the mirrored scheduler. Returned offers, published condition evidence and actual later admission replace private loss/cohort/uncommitted state. Distinct simultaneous pacing and deadline boundaries are checked. |
| Python forwarding | Added controlled rule-budget boundaries, complete signed timestamps, exact declared-check matching and invalid-command rejection after inspecting initial survivors. Full per-module scores are still pending. |
| Protocol message suites | Reviewed all 39 message cases and the remaining core protocol cases. Moved review and improvement cases into reference, framing, reflection and validation suites under the existing owner. Independent decoded fields supplement wire preservation, positive validation cases check complete bytes, and wire expectations cite dated sources. Full mutation scores and the final native CI matrix are still outstanding. |
| Build scripts | Added disposable binary targets for package-root `build.rs` files. A two-crate integration fixture killed all nine mutants, including deletion of the build script's configuration output. The real build scripts still require full-run survivor review. |

The case audit now records all 293 Rust cases and all 144 Python cases. The overall effort remains incomplete until the final revision passes every required full mutation group and CI profile and all actionable survivors are reviewed and repaired. Passing ordinary tests does not establish that result.

# Lifecycle case audit

These cases use per-test budgets and injected providers. Real threads exercise the lifetime contract, with channels, explicit release and bounded waits. Snapshot assertions below check the public resource diagnostics alongside actual admission. They do not inspect private storage or allocation layouts.

| Suite | Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- | --- |
| Runtime | `callback_tls_remains_charged_until_actual_exit_and_other_slots_recover` | Repaired. A TLS destructor holds one slot while another completes repeated work. Both slots admit work after release. | Returning admission before TLS destruction ends. |
| Runtime | `worker_admission_waits_for_a_released_permits_cleanup_slot` | Repaired. A controlled cleanup-slot handoff eventually admits and executes the replacement callback. | Rejecting a worker during the permit-to-cleanup handoff. |
| Runtime | `completed_workers_reuse_a_single_slot_runtime` | Repaired. Repeated callbacks return the expected result through the same finite runtime. | Leaking a permit after successful publication. |
| Runtime | `parent_cancellation_retains_callback_and_tls_charges_without_blocking_an_independent_root` | Repaired. Cancellation returns promptly, blocked work still refuses admission, an independent root works, and cleanup restores admission. Public diagnostics report retention. | Releasing the root while cancelled work or TLS cleanup still runs. |
| Runtime | `callback_panic_payload_cleanup_stays_owned_and_initialization_failure_is_retryable` | Repaired. Initialization can retry, panic destruction retains admission, and later work returns its result. | Releasing admission while an opaque panic destructor is blocked. |
| Operation | `cache_isolation_keeps_parent_root_and_retains_unfinished_worker_charges` | Repaired. Child operations saturate the parent root and cancellation cannot free a blocked callback. Both slots work after release. | Giving an isolated cache a separate worker budget. |
| Operation | `explicit_independent_root_remains_independent` | Repaired. An explicitly supplied root executes a callback while the parent refuses admission. | Ignoring the explicit runtime override. |
| Sink | `cooperative_publication_preserves_ack_and_has_no_worker_handoffs` | Repaired. All events arrive in order on the caller thread and return their expected acknowledgement with zero isolated capacity. | Dropping or reordering events, or starting an isolation worker. |
| Sink | `cancellation_during_cooperative_callback_prevents_success` | Retained. Cancellation during a callback returns the cancellation classification. | Reporting success after the callback cancels its parent. |
| Sink | `cooperative_errors_and_isolated_default_remain_explicit` | Retained. A callback error keeps its classification and an isolated callback cannot start with zero capacity. | Swallowing the callback failure or bypassing admission. |
| Sink | `forwarding_preserves_declared_delivery_and_generic_acknowledgements` | Retained. Forwarded events receive control and return their expected acknowledgement on the caller thread. Isolated delivery still needs admission. | Losing delivery mode or an acknowledgement during forwarding. |
| Native workers | `established_data_keeps_one_root_charge_without_execution_and_leaves_control_headroom` | Strengthened. Saturated sockets refuse more data but allow control work. Closing them permits another complete socket batch. Public diagnostics distinguish socket ownership from execution. | Double-charging sockets or leaking the data allocation. |
| Native workers | `a_socket_transfer_keeps_execution_until_the_work_really_finishes` | Strengthened. A transferred socket blocks further admission until its final owner releases it, then new work completes. | Releasing the shared root during socket promotion. |
| Native workers | `cancelled_unfinished_work_stays_charged_until_actual_completion` | Strengthened. Repeated retention marking preserves diagnostics and admission remains refused until the blocked task ends. Replacement work completes. | Releasing unfinished work or applying retention twice. |
| Native workers | `a_root_lease_retains_admission_without_retaining_finished_execution` | Strengthened. Completed work retains its root through the lease, and dropping the lease restores usable capacity. | Releasing a shared lease when only execution finishes. |
| Native workers | `unpromoted_socket_reservations_release_every_charge` | Strengthened. Success and panic without socket promotion both permit another saturated socket batch. | Leaking an unpromoted reservation on either exit path. |
| Native workers | `rejected_connect_dispatch_drops_captures_outside_lock_before_releasing_admission` | Repaired. A captured destructor reenters admission while refusal is still in effect, and later work completes. | Dropping captures under the pool lock or releasing admission before their destruction. |
| Native workers | `work_panic_payload_cleanup_stays_charged_after_caller_cancellation` | Strengthened. Cancellation retains a blocked panic destructor, then reports worker failure and permits successful replacement work. | Publishing the panic result before disposing its payload. |
| Native workers | `tcp_operation_budget_stays_charged_through_opaque_panic_cleanup` | Strengthened. Both a live and abandoned attempt retain their operation budget during panic cleanup. An injected TCP attempt reaches its expected refusal after release. | Freeing the operation lease when the caller abandons a pending attempt. |
| Native workers | `nested_lookup_allocation_stays_charged_through_cancelled_panic_cleanup` | Strengthened. Cancellation retains the nested lookup allocation and root, while control headroom remains usable. A later injected lookup returns its expected address. | Releasing only one of the two lookup leases during cleanup. |
| Native capture | `unfinished_group_readers_stay_charged_through_drop_until_actual_release` | Strengthened. Shutdown and drop retain every blocked reader. After release, the complete reader budget is reclaimed and replacement tasks execute. | Freeing readers on drop or leaking any member of the capture group. |
| Native capture | `inherited_elapsed_readiness_wait_retains_unfinished_native_work` | Repaired. Advancing an injected parent clock after a sampled time ends the readiness wait and retains unfinished work until release. | Checking inherited elapsed time only once. |
| Native capture | `inherited_elapsed_quiet_read_wait_retains_unfinished_native_work` | Repaired. The same clock advance ends a quiet read and preserves cleanup ownership. No exact clock-call count is assumed. | Restarting a local allowance after the parent expires. |
| Native capture | `zero_duration_native_poll_preserves_queued_records_and_cancellation_before_dequeue` | Strengthened. Cancellation leaves a queued frame intact. A later immediate poll returns its bytes and identity, then cleanup restores admission. | Dequeuing before checking cancellation or changing queued data. |
| Capture groups | `inherited_elapsed_group_readiness_cannot_report_success_after_provider_callback` | Retained. A provider-triggered clock advance prevents readiness success and cleanup runs once. | Accepting readiness without rechecking the parent. |
| Capture groups | `inherited_elapsed_quiet_group_wait_stops_without_restarting_local_allowances` | Retained. Explicitly coordinated clock advance ends a quiet group read and cleanup runs once. | Waiting on an independent local allowance. |
| Capture groups | `zero_duration_group_poll_still_drains_an_already_queued_record` | Retained. An immediate poll returns the injected frame bytes once, then reports no queued frame. | Refusing queued data solely because the local allowance is zero. |
| CLI followups | `bounded_ndjson_followup_sink_uses_no_workflow_handoff_and_flushes_each_record` | Repaired. A controlled refusal produces a complete flushed probe record with the expected endpoint and outcome. A terminal record follows with contiguous sequence. Thread assertions protect delivery isolation. | Omitting flush, changing probe fields or moving a cooperative callback to a worker. |
| CLI followups | `text_and_unisolated_writers_keep_the_isolated_callback_default` | Retained. These explicitly selected output configurations request isolated callback delivery. | Allowing a potentially blocking writer onto the caller thread. |
| CLI followups | `cooperative_followup_publication_retains_parent_control_inside_the_writer_wait` | Strengthened. A blocked writer stops the caller under cancellation or frozen-clock wall control, retains admission, and permits replacement work after release. | Losing parent control at the writer boundary. |
| CLI followups | `invocation_without_duration_applies_cancellation_to_initial_and_replacement_outputs` | Strengthened. Initial and replaced encoders inherit cancellation without a duration option, and replacement work succeeds after cleanup. | Dropping cancellation when applying output configuration. |
| Native registry | `queued_and_executing_requests_prevent_idle_retirement` | Strengthened. A queued request remains reachable, returns its expected reply and prevents retirement until completion. Retired admission is refused. | Retiring a queued or executing request, or losing its response channel. |
| Native registry | `request_arrival_and_retirement_have_no_unreachable_accepted_request` | Strengthened. Coordinated racing threads either deliver the accepted request or return the undelivered request with its response channel intact. | Accepting work after its worker becomes unreachable. |
| Native registry | `an_empty_inbox_retires_and_an_abandoned_initializer_stops` | Repaired. Idle admission is refused, abandonment disconnects queued replies, and stopped admission reports failure. Private serving flags are no longer inspected. | Leaving an abandoned request waiting or accepting work after shutdown. |
| Native registry | `sequential_historical_identities_recover_resident_capacity_and_root_headroom` | Repaired. Distinct live anonymous files pin controlled identities. Each namespace returns its expected reply, unrelated work executes, and the complete budget runs new callbacks after retirement. | Retaining historical cache entries, reusing another namespace's worker or leaking root admission. |
| Native registry | `checked_out_registry_wait_observes_inherited_elapsed_control` | Repaired. An armed fake clock confirms a sample during the wait before advancing. The held registry is released during bounded cleanup. | Checking parent time only before entering the registry wait. |
| Native registry | `full_inbox_wait_observes_inherited_elapsed_control_without_accepting_an_expired_request` | Repaired. The same observed clock advance refuses a blocked request. Every original request still delivers its expected reply, with no expired request admitted. | Losing queued requests, admitting expired work or failing to recheck inherited time. |
| Native registry | `native_operation_wait_checks_parent_cancellation` | Retained. An injected pending operation reports its cancelled parent and aborts the controlled connection task. | Waiting only for the local timeout after cancellation. |
| Native registry | `native_operation_wait_retains_inherited_elapsed_control_as_well_as_wall_timeout` | Retained. The operation advances an injected parent clock while pending, and the wait reports the expected elapsed classification. | Resetting the inherited allowance at an async boundary. |
| Native registry | `ready_native_operation_cannot_report_success_after_it_interrupts_its_parent` | Retained. A ready result that cancels or expires its parent returns the corresponding refusal. | Publishing success without checking control after the operation completes. |

Registry fixtures use the pinned development-only tempfile library rather than process-named directories that can survive failed runs. Keeping all anonymous files alive prevents inode reuse from weakening the historical-identity case. The controlled workers retire through the registry during the bounded test rather than relying on the production idle timer. Every reply and recovery wait is bounded.

# Scan case audit

Adaptive tests use supplied relative times and explicit pacing fixture inputs. They check returned selections, completed work, response-budget effects and published scheduling evidence. No scheduler implementation is duplicated as an oracle. The connect fixture uses a fixed timestamp. The original ten cases are preserved, and an independent two-paced-host case retains coverage previously present in the removed mirror.

| Suite | Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- | --- |
| Adaptive | `every_host_endpoint_is_selected_once_and_completed` | Retained. Every supplied host and endpoint receives a distinct sequence, completes and stops producing offers under a one-slot budget. | Duplicating, omitting or misidentifying an endpoint. |
| Adaptive | `unadmitted_selections_remain_eligible_and_retry_identity_is_stable` | Retained. Unadmitted work remains eligible and retries retain expected identities at their configured time. | Consuming a discarded offer or retrying the wrong endpoint. |
| Adaptive | `expiry_counts_unsent_attempts_once_and_pending_settlement_remains_valid` | Strengthened. Expiry accounts for unsent attempts once, accepts late settlement and reports the exact incomplete host. | Double-counting a late result or attributing incompleteness to the wrong host. |
| Adaptive | `selection_timeline_preserves_pacing_retries_discarded_offers_and_expiry` | Repaired. An independent timeline covers partial admission, omission, retries, paced boundaries, a shortened final allowance and late settlement. | An oracle sharing a selection defect or losing a discarded offer. |
| Adaptive | `paced_host_cannot_queue_again_before_its_admission_commits_or_is_omitted` | Repaired. Uncommitted admission blocks more work, omission restores an offer, and committed sends pace remaining endpoints through completion. | Releasing admission too early or retaining it after omission. |
| Adaptive | `paced_hosts_keep_independent_admission_and_ready_times` | Added. Both paced hosts receive initial offers and later work follows independent 10 ms and 20 ms boundaries. | Applying one host's pacing globally or suppressing the second paced host. |
| Adaptive | `provisional_silence_retries_neutrally_and_only_final_clean_quality_promotes_losses` | Repaired. An independent coverage table controls later admission, incomplete identities and complete rate-limit evidence. Requalification cannot apply old losses again. | Qualifying unknown capture evidence or halving capacity twice. |
| Adaptive | `deferred_interface_admission_preserves_host_pacing_across_refill_polls` | Strengthened. Another host refills while an offer waits for commitment. Commitment restores the final paced endpoint and the stage completes. | Offering more paced work before commitment or leaking admission afterward. |
| Connect | `local_deadline_is_unavailable_for_both_control_and_port_inference` | Strengthened. Local failures remain unavailable, silence has the expected inference, and connected/refused replies preserve latency, responder and supporting sequence. | Treating local expiry as network silence or losing response evidence. |
| Deadline index | `polls_release_only_due_probes_in_original_order` | Strengthened. Interleaved deadlines release only due identities, then combine draining work in original order. | Releasing a later deadline early or ordering ready work by deadline. |
| Deadline index | `removal_and_reuse_leave_no_stale_deadlines_or_draining_entries` | Retained. Removal and identity reuse leave only the new deadline and result. | Returning stale cancelled work or dropping its replacement. |

# CLI output case audit

These cases check emitted documents, externally observed writes and rendered error content. A controlled writer can recover after a refusal, so an unintended retry changes observable bytes. Its byte budget works across arbitrary write chunks. Serialization cases permit different buffering decisions and no longer inspect invocation flags or write-call counters. Length budgets are checked against complete encoded output, with semantic content checked independently.

| Suite | Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- | --- |
| JSON | `error_handling_json_serialization_failure_never_publishes_a_second_document` | Repaired. Failed serialization retains the expected error classification and only a valid output prefix. A terminal attempt cannot change published bytes. | Retrying a partial document or publishing another document after failure. |
| JSON | `error_handling_json_write_and_flush_failures_do_not_retry_buffered_bytes` | Repaired. Write and flush refusals preserve the expected bytes and cannot complete later delivery through an implicit retry. | Retrying buffered bytes during writer destruction or a terminal report. |
| JSON | `error_handling_json_prepublication_cancellation_still_allows_terminal_report` | Strengthened. Cancellation publishes no initial bytes, while the allowed terminal document contains the expected command and error fields. | Consuming publication admission before checking cancellation. |
| JSON | `json_budget_accepts_complete_output_and_distinguishes_serialization_failures` | Added. Compact and pretty output fit exact byte budgets and fail below them. Serialization errors remain distinct from size refusals. | Counting characters, miscounting formatting bytes or misclassifying serialization failure. |
| Human errors | `error_handling_text_renders_coordinates_and_sanitizes_details` | Retained. Every supported coordinate and escaped untrusted detail appears in rendered output. | Dropping coordinates or emitting raw control characters. |
| Human errors | `error_handling_reporting_failure_keeps_original_and_stops_after_fallback` | Strengthened. Actual fallback text preserves the original failure, reporting failure and cause, while the exit status reflects failed reporting. | Skipping fallback entirely or discarding the original failure. |
| Human errors | `error_handling_successful_reporting_keeps_requested_exit_status` | Strengthened. Successful output contains the original error and retains each supplied exit status without falling back. | Returning a status without emitting the error or replacing its requested status. |
| DNS output | `fields_publish_the_expected_dns_question_and_compressed_answers` | Repaired. Compact, pretty and mapped publication each match independent typed fields from a cited compressed DNS vector. | Two output paths agreeing on a wrong name, record, flag or field type. |
| Security output | `published_security_fields_and_nulls_are_frozen` | Retained with a valid controlled digest. Independent expected JSON preserves findings, explicit nulls, completeness, source identity and every severity spelling. | Omitting a published field or changing its meaning during conversion. |

# CLI documentation and input case audit

The original sixteen cases remain in their mapped files and one cross-manifest budget case was added. Expected file contents, input payloads and error origins replace incidental artifact counts and negative-only success checks. Static HTML checks cover escaped report content and the initial finding count. They do not claim browser layout, filtering or accessibility interaction coverage.

| Suite | Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- | --- |
| Documentation | `new_documentation_uses_normal_creation_permissions` | Strengthened. Known rendered files contain their supplied contents and receive the same creation permissions as an ordinary file created in the controlled directory. | Publishing no files or creating documentation with temporary-file permissions. |
| Documentation | `regeneration_atomically_replaces_existing_regular_files` | Strengthened. Both existing files receive the complete replacement contents and pre-observed permissions survive replacement. | Leaving a later file stale or dropping existing permission bits. |
| Documentation | `render_failure_and_unsupported_formats_do_not_create_directories` | Retained. Controlled render failure has path context, and unsupported output formats leave the absent output directory untouched. | Touching the destination before rendering or format validation succeeds. |
| Documentation | `write_and_sync_failures_leave_all_originals_intact` | Strengthened. Injected stage, write or sync failure preserves both original contents and the complete expected file set. | Publishing a staged prefix too early or leaving temporary files after failure. |
| Documentation | `publication_failure_reports_the_published_prefix_and_destination` | Retained. Publication refusal reports the destination and already-published prefix, with the first file complete and the caller's blocking directory intact. | Hiding partial publication or replacing the blocked destination. |
| Documentation | `cancellation_at_publication_reports_destination_and_published_prefix` | Retained. Controlled cancellation stops publication at the second destination and reports the complete first file as the published prefix. | Publishing after cancellation or losing the partial-output context. |
| Documentation | `actual_render_includes_completions_and_grouped_manuals` | Strengthened. Every supported shell produces completion content for the program and representative commands. Root, group and registered command manuals contain their owned descriptions. Destinations remain unique. Paths derive from the generator API, and no arbitrary artifact count is pinned. | Omitting a registered manual, rendering the wrong command's description or producing empty completion content. |
| Documentation | `replacement_rejects_directory_and_symlink_destinations` | Strengthened. Unsafe destinations are refused while existing directory contents, symlink targets and regular-file contents remain intact. Socket destinations are also refused on Unix. | Clobbering an existing object while reporting a refusal. |
| Help | `inline_and_block_examples_survive_short_help` | Strengthened. Inline and block examples retain their text, blank sections are absent, and the short-help limit keeps the first three examples. | Losing an inline example, including trailing detail or ignoring the short-help bound. |
| Help | `every_is_a_frame_selection_option` | Repaired. Both frame-selection options independently map to the user-facing selection section. | Two incorrectly classified options agreeing with each other. |
| Bounded input | `error_handling_reads_retain_file_or_stdin_and_causes` | Retained. Injected read failure retains the file or stdin context and the supplied cause. | Losing input identity or replacing the underlying read diagnostic. |
| Bounded input | `error_handling_file_bounds_and_missing_files_retain_paths_and_codes` | Strengthened. Complete boundary inputs return their actual bytes, excess input has the expected resource classification, missing and empty required inputs retain context, and the explicit empty-input entry point permits empty data. | Rejecting every input, truncating a boundary file or applying required-input behavior to the empty-input API. |
| Manifest input | `error_handling_manifest_utf8_keeps_physical_line_and_decode_cause` | Repaired. Invalid UTF-8 reports the exact physical line and retains the underlying decoder cause without pinning a library diagnostic spelling or cause count. | Losing line context or the actual decoding cause. |
| Manifest input | `declarations_keep_physical_origins_and_share_manifest_budgets` | Added. Multiple manifests retain independent tokens, source paths and physical lines at the combined byte and line boundaries. Reducing either budget refuses the second source at the correct line. | Resetting a budget for each file or failing to charge blank and comment lines. |
| Recipe input | `error_handling_recipe_decoding_and_parsing_keep_file_and_causes` | Strengthened. Invalid file data preserves classifications, paths and the actual UTF-8 cause. Valid document and inline recipes return the complete expected raw layer and payload bytes. | Rejecting valid input, dropping payload bytes or detaching errors from the supplied file. |
| Security HTML | `assessment_escapes_untrusted_findings_and_preserves_report_content` | Repaired and renamed from `searchable_assessment_escapes_untrusted_content_and_keeps_findings_visible`. Two findings retain independent rule, severity, subject, summary, indicator, frame, evidence and remediation content. Sources, completeness reasons and the initial visible count survive. Supplied markup is escaped without class or attribute-order assertions. | Omitting a later finding, dropping evidence or emitting untrusted markup literally. |
| Security HTML | `escape_untrusted_markup` | Strengthened. A cited HTML character-reference vector escapes syntax characters, preserves Unicode and escapes a literal entity marker. | Leaving a syntax character active or incorrectly treating literal entity text as already safe. |

# Core expression, provenance and message case audit

All 31 cases remain in their mapped files. These tests use controlled capture bytes, independent expected fields and supplied relative times. Regressing source timestamps distinguish physical frame ordering from clock ordering. Advertised protocol fixtures define the required stream coverage independently of the decoder's capability predicate. Existing admission-refusal and recovery cases remain.

| Suite | Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- | --- |
| Expression syntax | `crossed_delimiters_fail_at_the_crossing_and_quotes_are_preserved` | Strengthened. Crossed delimiters report the supplied base-relative byte offset and expected offending character. Balanced, quoted, escaped and multibyte segments retain their exact text and offsets. | Splitting a quoted comma, reporting character offsets instead of byte offsets, or discarding quoted text. |
| Field transforms | `assignment_limit_precedes_compilation` | Strengthened. Over-budget assignments produce the assignment-limit classification before parsing. At the accepted count the deliberately invalid path reaches its specific syntax refusal. | Returning an unrelated error while the old test only checked that it was not a limit error. |
| Provenance | `retirement_preserves_key_order_active_entries_and_omission_counts` | Retained with stronger fixture timestamps. Active entries stay retrievable, retired entries have deterministic physical-frame ordering, and omitted outcomes are counted. | Sorting source output by timestamp or retaining a retired key. |
| Provenance | `assembly_orders_and_deduplicates_sources_without_changing_published_sets` | Strengthened. Assemblies and unions have independent expected source lists, including a disjoint union member, while published inputs retain their contents. | Returning one union operand unchanged or mutating an already published set. |
| Provenance | `refused_inserts_and_freezes_preserve_sources_and_release_their_budget` | Retained. Saturated admission refuses insertion/freeze without corrupting source sets, then released capacity admits a complete replacement assembly. Distinct timestamps remain attached. | Losing sources on refusal or leaking admission across attempts. |
| Provenance | `shared_sources_hold_admission_until_the_last_owner_releases_them` | Retained. Shared ownership keeps admission occupied after one owner drops, and release of the final owner restores usable capacity. | Releasing a shared source charge too early or never releasing it. |
| Provenance | `foreign_sources_are_refused_without_changing_the_assembly` | Retained. Sources from another capture cannot enter an assembly or union, and the original assembly still freezes correctly. | Mixing capture identities or partially applying a refused insertion. |
| Message analysis | `split_mqtt_and_coalesced_messages_keep_sources` | Strengthened. Every split preserves independent MQTT fields, exact message bytes, distinct source timestamps and contributing frames. A later message completes under the same small buffer limit. | Dropping split payload bytes or leaking the completed message's buffer budget. |
| Message analysis | `gap_stops_direction_until_new_generation` | Strengthened. A gap emits the expected issue and retained partial bytes with their original source, blocks the old generation and permits a complete sourced message in the next generation. | Dropping the partial message or accepting old-generation data after a gap. |
| Message analysis | `every_tcp_protocol_accepts_split_and_coalesced_frames` | Strengthened. Each independently advertised TCP protocol is exercised at every split and coalesced. Exact bytes, contributing frames and owned document-fixture fields are checked, with explicit directional Modbus expectations. | Silently skipping a protocol whose capability flag regressed, or publishing a placeholder decoded packet. |
| Message analysis | `declared_length_is_rejected_before_large_allocation` | Strengthened. Large OPC UA and RESP declarations produce the specific configured buffer-limit refusal. | Treating a policy refusal as malformed or unsupported framing. |
| Message analysis | `port_overrides_drive_stream_selection` | Strengthened. The custom port produces the expected complete MQTT bytes, decoded protocol, destination and source frame. | Selecting the codec without retaining a usable message. |
| Message analysis | `capture_pipeline_reassembles_and_attributes_messages` | Strengthened. The owned PCAP emits two independently expected messages with the correct contributing physical frames and matching complete-message summary. | Retaining the right number of events while losing payload content or attributing the wrong source frames. |
| Message analysis | `review_selected_source_port_is_not_hidden_by_an_unselected_destination` | Strengthened. A selected source port still produces the exact ping response and decoded packet type when the destination maps to an unselected protocol. | Letting destination selection suppress a valid source-selected protocol. |
| Message analysis | `review_mqtt5_stays_opaque_in_both_directions_until_a_new_generation` | Strengthened. Unsupported MQTT 5 framing preserves all five exact forward/reverse messages, their sources and unsupported diagnostics. A later MQTT 3.1.1 generation produces complete packets. | Dropping opaque payload bytes, losing reverse-direction version state, or carrying unsupported state into a new generation. |
| Message analysis | `review_events_before_the_first_delivery_disable_the_generation` | Repaired. Expected issue classifications and reverse-direction behavior come from the supplied event, not from the emitted issue. A new generation recovers. | Misclassifying a gap as reset and letting the incorrect output choose its own expected behavior. |
| Message analysis | `review_amqp_unsupported_version_keeps_both_directions_opaque` | Strengthened. The unsupported preface and both retained directional tails preserve exact bytes and source frames through finalization. The summary counts those three messages. | Discarding unsupported bytes while retaining only the status or summary count. |
| Message analysis | `review_capture_stops_early_conflicts_and_gaps_until_tuple_reuse` | Strengthened. Explicit capture-time expiry and conflict inputs block old data. The sole complete replacement message has the expected generation, bytes and final physical source. | Depending on a production expiry default or manufacturing a complete message from conflicted data. |
| Message analysis | `review_server_first_payload_uses_the_handshake_server_port` | Strengthened. With or without the initial SYN, distinct server/client BGP messages retain independent wire bytes, AS numbers, identifiers, source ports and physical frames. | Returning a BGP label without the expected peer data or inferring the role from the wrong port. |
| Message analysis | `review_sip_keepalives_across_deliveries_do_not_disable_messages` | Strengthened. Every split excludes keepalive bytes from messages, preserves source spans, and exposes the expected SIP start line and empty body. Finalization has no leftover message. | Treating keepalives as messages or losing a header when a CRLF crosses deliveries. |
| Message analysis | `review_modbus_uses_handshake_roles_and_preserves_ambiguous_pdus` | Strengthened. Controlled transactions produce independent request/response bytes, IDs and register values with a handshake. Without known roles, raw PDU bytes are retained. | Guessing direction from ambiguous ports or returning the correct form label with wrong register data. |
| Message analysis | `review_many_coalesced_messages_preserve_the_layer_budget_and_stream` | Repaired. Dissection stays within the supplied layer limit, decodes when room is available and preserves the complete application payload across decoded messages and the raw tail. Stream analysis emits every exact sourced message. | Enforcing an incidental exact layer count, losing a raw tail, or publishing empty messages for the retained count. |
| Message analysis | `review_declared_buffer_limits_are_policy_errors_for_every_segmentation` | Strengthened. Both segmentations refuse oversized declarations with the expected policy classification. Exact-budget messages retain bytes and sources, then admit another message after release. | Reclassifying resource refusal or failing to release a completed message's buffer. |
| HTTP/2 headers | `regular_names_accept_exactly_the_lowercase_token_bytes` | Retained. Every byte is checked against an independent protocol token set, including the uppercase refusal diagnostic. | Using a Unicode or case-insensitive token predicate for field names. |
| HTTP/2 headers | `pseudo_names_keep_lowercase_and_token_rules` | Retained. Pseudo names retain the colon grammar, lowercase rule and meaningful empty/invalid-token refusals. | Accepting an empty pseudo name or an embedded colon in a regular name. |
| HTTP/2 headers | `request_validation_keeps_token_case_rules_for_method_and_protocol` | Strengthened. Valid method case and CONNECT authority are retained. Malformed protocol values are refused alongside the existing pseudo-header order and name checks. | Ignoring malformed `:protocol` values or losing request metadata. |
| HTTP/1 codec | `request_start_requires_exactly_three_components` | Retained with a primary-source reference. A valid line has independently expected method, target and version, while missing, empty or extra components fail. | Accepting an extra request-line component or collapsing an empty target. |
| YAML documents | `yaml_accepts_one_document_with_comments_and_terminators` | Repaired. An explicit expected document contains the known raw payload for every supported comment/marker form. The expected value no longer comes from the same parser. | A shared parser defect changing both the input result and the old expected document. |
| YAML documents | `yaml_rejects_second_documents_including_empty_ones` | Retained. A second document, including empty and directive-prefixed forms, produces the syntax classification. | Ignoring trailing documents after a valid first packet. |
| YAML documents | `yaml_rejects_malformed_trailing_content` | Retained. Invalid trailing syntax is reported as a YAML usage failure rather than accepted or misclassified as a resource limit. | Stopping validation at the first complete document. |
| YAML documents | `yaml_preserves_resource_limit_classification` | Strengthened. Exact input-byte and layer allowances preserve the payload. Smaller allowances report their specific resource limit and usage classification. | Treating an accepted boundary as over budget or converting a limit failure into generic syntax. |

# Remaining CLI case audit

All 53 remaining CLI cases have been reviewed. Inputs are controlled reports, packets and settings. Retained-example consistency is distinct from producer execution. Callback tests assert delivered diagnostics after the callback returns, and output tests protect consumer-visible bytes without depending on write-call counts.

| Suite | Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- | --- |
| Errors | `error_handling_context_and_secondary_failure_preserve_primary_details` | Repaired. Primary classification, source coordinate, capture data and a nonempty failed-probe payload survive secondary output failure. | Replacing scan evidence with a default payload or losing the original cause. |
| Stream selectors | `stream_indexes_are_unsigned_decimal` | Retained. Signed, empty, non-ASCII and overflowing indices fail. TCP zero and padded UDP indices produce independent expected references. | Accepting signed indices or selecting the wrong transport or index. |
| Frame ranges | `positions_are_always_one_based` | Retained. Frame zero is excluded and the first physical frame remains selected. | Treating frame positions as zero-based. |
| Frame ranges | `overlapping_ranges_intersect_sampling_without_losing_boundaries` | Retained. Independent selected positions cover overlap, sampling and the maximum supported position. | Applying sampling before the wrong range union or dropping an endpoint. |
| Frame ranges | `invalid_ranges_and_zero_sampling_report_usage_errors` | Retained. Malformed ranges keep the frame-selection usage code and exit status. Zero sampling is refused. | Accepting an ambiguous range or reporting the wrong failure class. |
| Frame ranges | `explicit_noop_selections_keep_verbatim_fast_path` | Retained. Equivalent unrestricted selections remain unrestricted, while a selection starting at frame two is restrictive. | Discarding a real restriction or failing to recognize an explicit no-op selection. |
| Link type | `numeric_link_types_use_unsigned_decimal_syntax` | Retained. The u32 boundary and named Ethernet type resolve correctly. Signed, hexadecimal and overflowing forms fail. | Permitting an unsupported number spelling or overflowing the link type. |
| Decode override | `decode_as_ports_are_unsigned_decimal_with_whitespace` | Retained. A padded decimal binding selects the expected DNS codec. Empty, zero, signed, overflowing and non-ASCII ports fail. | Accepting an invalid port or losing the override binding. |
| Timestamps | `fractional_seconds_scale_without_losing_leading_zeroes` | Retained. Independent nanosecond values verify decimal scaling and malformed timestamp spellings fail. | Scaling a fraction by its numeric value instead of its digit width. |
| Stream output | `complete_record_limit_includes_newline_and_zero_budget_is_refused` | Repaired naming. The complete serialized record includes its newline at the exact byte boundary. Smaller and zero budgets fail. | Omitting the newline from admission accounting. The case does not claim serializer-failure coverage. |
| Stream output | `failed_partial_write_is_terminally_failed_without_a_false_complete_or_later_flush` | Repaired. A cumulative byte allowance permits a prefix before one recoverable refusal. Later completion and cleanup cannot append or flush it, and worker admission recovers. | Retrying buffered output after failure, coupling the fixture to write-call boundaries or leaking the worker slot. |
| Stream output | `cancelled_bounded_writer_keeps_actual_work_charged_and_never_returns_complete` | Retained. Explicitly coordinated blocked writing outlives caller cancellation, retains admission and later publishes the supplied message before capacity recovers. | Releasing admission while writing remains active or acknowledging false completion. |
| Stream output | `a_started_complete_write_can_finish_after_cancellation_without_acknowledging_success` | Retained. A started terminal write may drain after cancellation, while the caller receives failure and the complete worker budget eventually recovers. | Returning completion success after cancellation or dropping already-started output. |
| Multipath output | `aggregate_and_stream_preserve_the_same_multipath_evidence` | Repaired. Independent flow, completion, RTT, topology, summary and flow-summary values now accompany aggregate/stream parity and raw frame/timestamp checks. | A shared conversion changing both encodings in the same incorrect way. |
| Multipath examples | `checked_in_stream_reconstructs_the_aggregate_topology` | Retained as asset validation. The owned stream fixture reconstructs the owned aggregate fixture with contiguous records and one completion. | Shipping examples that disagree about probes, edges or completion. This case does not execute the producer. |
| Application output | `ndjson_application_enforces_result_budget_and_flushes_complete_records` | Retained. Every supplied result becomes a complete visible record with its expected sequence. Budget exhaustion leaves output unchanged and a terminal summary can follow. | Dropping results, failing to flush or admitting one result beyond the budget. |
| Application output | `budget_and_serialization_failures_write_no_prefix_and_allow_one_error_terminal` | Retained. Policy and serialization failures stay distinct, publish no prefix and allow one complete error terminal. | Publishing partial data before refusal or allowing duplicate terminal records. |
| Application output | `writer_failure_prevents_false_success_or_repair_terminal` | Retained. A writer refusal has the output-error classification and prevents later success or error-repair publication. | Acknowledging completion or reopening an encoder after a failed write. |
| Application output | `cancellation_during_serialization_refuses_write_and_terminal_cleanup_remains_usable` | Retained. Cancellation from serialization prevents output bytes and leaves terminal error cleanup usable. | Failing to recheck control after serialization. |
| Application output | `diagnostics_observe_live_settings_on_initial_and_replacement_outputs` | Retained. Published resource settings track a controlled enabled-to-disabled change on both encoder paths and remain absent when diagnostics are disabled. | Retaining a stale settings snapshot after output replacement. |
| Application output | `preexisting_encoder_deadline_survives_initial_and_replacement_configuration` | Retained. An injected expired encoder deadline prevents completion and all bytes despite a longer invocation allowance. | Replacing inherited control with a fresh local allowance. |
| Traceroute arguments | `multipath_arguments_require_opt_in_and_preserve_legacy_defaults` | Repaired. Invalid opt-in and flow ranges fail. Prepared requests retain the supplied attempt count and evidence limits, and overflowing source-port ranges fail. | Accepting success while discarding requested probe or resource settings. |
| Assessment sources | `source_provenance_preserves_first_seen_order_and_distinct_hashes` | Retained. Independent source pairs verify first-seen order, duplicate removal and preservation of different content under one path. | Sorting source output or conflating different hashes. |
| Assessment redaction | `redacts_cookies` | Repaired. An independent complete document checks cookie redaction and nested sensitive values while retaining names, flags and unrelated content. | Removing the entire document or redacting unrelated value fields. |
| Message arguments | `protocol_selection_rejects_datagram_only_codecs` | Retained. A datagram-only protocol is refused and case-insensitive MQTT selects the expected stream protocol. | Admitting an unsupported stream codec or losing case normalization. |
| Dispatch | `generator_cancellation_maps_to_interrupt_status_after_diagnostic_write` | Repaired. Exactly one captured cancellation diagnostic accompanies the independent public interrupt status. | Skipping the reporter while still returning the expected status. |
| Dispatch | `generator_diagnostic_write_failure_precedes_cancellation_status` | Repaired. The attempted original diagnostic is captured and a reporting failure overrides cancellation status. | Returning cancellation status despite a failed diagnostic write. |
| Dispatch | `error_handling_json_reporting_failure_keeps_original_diagnostics` | Repaired. The attempted JSON error and fallback diagnostic independently retain the original message, cause and source coordinate alongside the write failure. | Skipping a callback or replacing the original error with an output error. |
| Dispatch | `error_handling_json_after_publication_uses_stderr_and_prioritizes_output_failure` | Repaired. After an established JSON attempt, stderr receives one expected diagnostic and output failure takes precedence over cancellation. | Attempting a second JSON document or suppressing stderr reporting. |
| Dispatch | `error_handling_ndjson_cancellation_reports_one_terminal_record_or_io_failure` | Repaired. Cancellation produces the expected complete error record or a captured output-failure diagnostic. A later error cannot append bytes. | Relying on private encoder flags while failing to publish the terminal error. |
| Dispatch | `error_handling_failed_ndjson_preserves_context_and_original_cause` | Repaired. An already failed stream leaves bytes unchanged and reports the original probe coordinate and causes through one fallback record. | Losing original error context when reporting an incomplete stream. |
| Packet input | `bounded_hex_preserves_syntax_and_classifies_size_errors` | Repaired. Valid formatted hexadecimal decodes independently. Excess decoded bytes have explicit policy code, kind and size evidence. Malformed and empty inputs fail. | A shared classifier hiding an incorrect failure class. |
| Packet input | `bounded_hex_rejects_oversized_text_and_extra_nibbles` | Repaired. Otherwise-valid hexadecimal with excessive whitespace is refused by the text budget. An extra nibble also exceeds the decoded budget. | Removing the text bound while an all-whitespace fixture still fails for being empty. |
| Security options | `completion_and_severity_gates_are_opt_in_and_combine` | Retained. Complete and incomplete reports, finding completeness and high/low severities exercise the opt-in gates and their combination. | Enabling gates by default, using the wrong severity boundary or combining gates with AND. |
| Security input | `stdin_source_validation_and_consumed_bytes_preserve_identity` | Repaired naming and citation. Pure source validation rejects multiple stdin declarations. A cited independent SHA-256 vector preserves the supplied path and consumed-byte digest. | Accepting multiple stdin consumers or hashing different input. Caller I/O ordering is outside this case. |
| Scan comparison input | `cli_adapter_preserves_the_legacy_comparison_contract` | Repaired. Independent unchanged, changed, unavailable, coverage and invalid-input expectations now accompany legacy parity. Directional severity, evidence, measurements and limit classifications are checked. | Two comparison entry points agreeing on the same wrong findings or error class. |
| Statistics arguments | `unsupported_table_options_fail_validation` | Retained. Unsupported table/option combinations fail selection validation and a supported combination succeeds without accessing the placeholder input path. | Accepting an unsupported presentation option or rejecting valid selection arguments. |
| Statistics selection | `duration_ranking_uses_volume_and_stream_ties_before_top` | Retained. Independent stream order verifies duration, frame, byte and stream tie-breaks before top truncation. | Taking the top rows before applying ranking or reversing a tie-breaker. |
| Statistics selection | `minimum_frames_filters_before_ranking_without_changing_overview_totals` | Repaired. The selected protocol and conversation, unchanged overview totals and distinct filtered diagnostic categories are independently expected. | Emitting duplicate or incorrect diagnostic categories while row counts still match. |
| Statistics selection | `threshold_and_top_report_separate_omissions` | Retained. The expected protocol remains after filtering and truncation, with separate filtered and omitted diagnostics. | Conflating threshold filtering with top-list omission. |
| Statistics selection | `minimum_frames_applies_to_ports_and_io_and_zero_keeps_rows` | Retained. A zero threshold retains port rows and higher thresholds remove the supplied port and I/O rows. | Ignoring a table-specific threshold or treating zero as a restrictive threshold. |
| Scan selection | `live_port_selection_requires_omitted_ports` | Retained. A live TCP selection without destination ports has the independently expected diagnostic. | Starting a live port scan with no port selection. |
| Scan selection | `listing_omits_an_unrequested_default_port_selection` | Retained. An unrequested listing selection returns no implicit endpoint selection. | Introducing a default port scan into listing behavior. |
| Scan selection | `ip_protocol_only_selection_uses_protocol_endpoints` | Retained. The supplied protocol inclusion and exclusion produce the expected remaining protocol endpoint and exclusion count. | Treating portless IP protocols as transport ports or ignoring exclusion. |
| Scan selection | `invalid_port_and_protocol_combinations_keep_their_messages` | Retained. Three invalid transport/port/protocol combinations have independent usage diagnostics. | Accepting options for an incompatible transport or reporting the wrong cause. |
| Scan selection | `listing_preserves_icmp_combined_invalid_option_precedence` | Retained. Listing and live selection retain their independently expected precedence for combined invalid ICMP options. | Changing the user-visible validation precedence. |
| Scan selection | `transport_specific_exclusions_only_remove_matching_endpoints` | Retained. A controlled mixed TCP/UDP selection retains the exact endpoints not covered by the TCP exclusion. | Removing the same port from every transport. |
| Scan selection | `scan_exclusions_keep_terms_discovery_did_not_consume` | Retained. After discovery consumes its transport terms, the remaining scan exclusion still removes the intended TCP endpoint. | Dropping an exclusion needed by the later scan. |
| Scan discovery selection | `tcp_and_tcp_ack_discovery_expansion_is_deduplicated_and_counted` | Retained. Repeated probe declarations produce the exact distinct TCP and TCP-ACK probes and exclusion count. | Duplicating discovery probes or losing one probe kind. |
| Scan preparation | `rejects_multiple_stdin_consumers` | Retained. Multiple stdin declarations produce the expected usage exit and diagnostic. | Accepting ambiguous stdin consumption. |
| Scan preparation | `list_rejects_discovery` | Retained. Listing with active discovery has the expected usage exit and diagnostic. | Allowing a listing command to trigger discovery. |
| Scan preparation | `list_rejects_reverse_dns` | Retained. Listing with reverse DNS has the expected usage exit and diagnostic. | Allowing a listing command to start reverse resolution. |
| Scan preparation | `list_rejects_traceroute` | Retained. Listing with traceroute has the expected usage exit and diagnostic. | Allowing a listing command to send traceroute probes. |

# Remaining facade case audit

All 48 cases remain in their owning suites. Six cross-provider cases moved from the legacy improvement file to root `tests.rs`. Returned candidates, decoded/transmitted bytes, provider refusals and published events replace shared oracles and private bookkeeping. The sole visibility change exposes the existing internal event drain to these crate tests.

| Suite | Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- | --- |
| Network | `absolute_hostname_and_resolver_spelling` | Strengthened. Absolute hostname normalization preserves its trailing dot through display, serialization and resolver input, then returns the expected authorized address and declaration. | Losing the absolute spelling or returning an empty resolution. |
| Network | `clock_stops_at_spent_deadline` | Repaired. A coordinated worker completes a requested long sleep under spent control within a bounded wait. | Sleeping for the full requested delay after the deadline has expired. |
| Network | `interface_ambiguity_and_late_enumeration` | Retained. Ambiguous names and indices are refused, and cancellation during enumeration outranks its result. | Arbitrarily selecting one interface or returning a late result after cancellation. |
| Network | `route_deadline_cache_and_identity` | Repaired. Cached route contents remain available after the provider is disabled, expired operations do not query it, and late or invalid route identities are refused. | Requerying a cached route, ignoring control or accepting an invalid interface identity. |
| Network | `numeric_and_custom_resolution_boundaries` | Strengthened. A live numeric target returns its address without hostname lookup; spent or inherited control refuses numeric and custom resolution. | Invoking hostname resolution for a numeric target or accepting a late custom result. |
| Network | `distinct_resolver_order_and_limit` | Retained. Duplicate addresses retain first-seen order and only distinct values count toward the supplied limit. | Reordering results or counting duplicates as distinct addresses. |
| Neighbor | `incomplete_capture_identity_never_reaches_injected_provider` | Strengthened. Incomplete names or indices are refused before capture and leave no transmitted packet. | Passing an unusable capture identity to a live provider. |
| Neighbor | `parent_cancellation_reaches_reads_and_prevents_unsent_attempts` | Repaired. Cancellation reaches the read's inherited control and yields either no transmission or the exact already-started request. No capture-read count is assumed. | Losing inherited cancellation or sending after cancellation before admission. |
| Neighbor | `interrupted_read_retains_sent_attempt_and_capture_evidence` | Strengthened. A read interruption retains the sent attempt, exact request bytes, captured frame bytes and cancellation classification. | Losing already-observed evidence during error propagation. |
| Neighbor | `dequeued_frame_survives_wait_interruption` | Retained with a fixed packet timestamp. A clock advance during a read preserves the dequeued frame and sent-attempt result without marking truncation. | Discarding the frame after a post-read deadline check. |
| Policy | `resolution_policy_denial_preserves_classification_and_causes` | Retained. Hostname denial retains its declared name and underlying classification and never invokes the resolver. | Performing denied resolution or losing policy error identity. |
| Policy | `resolution_target_failure_preserves_classification_and_causes` | Retained. An injected resolver failure retains the supplied cause and expected I/O classification. | Replacing the source failure with an unrelated policy error. |
| Policy | `resolution_deadline_interruption_preserves_target_control` | Retained. Numeric resolution under an immediate deadline reports target control with its original classification and cause chain. | Treating a deadline refusal as ordinary resolution failure. |
| Preparation | `interrupted_neighbor_io_preserves_sent_request_statistics` | Retained. Injected neighbor failure preserves the already-sent request's public packet and byte statistics and error identity. | Dropping discovery traffic from failure evidence. |
| Preparation | `multipath_source_change_is_rejected_before_capture_or_transmission` | Retained. A refreshed source that differs from the pinned multipath route is refused without capture or transmission. | Sending a later flow with a changed source identity. |
| Preparation | `retained_and_rebuilt_previews_preserve_packet_bytes` | Repaired. Both preparation paths produce independent expected IP, UDP and payload fields, and the transmitter receives those complete bytes. | Two faulty builds agreeing while emitting the wrong packet. |
| Preparation | `bounded_windows_admit_and_materialize_every_packet` | Repaired. Complete windows fit a budget based on actual encoded bytes, materialize every expected packet and continue refusing extra admission. | Charging materialization twice or resetting cumulative admission. |
| Preparation | `changed_final_declaration_is_authorized_before_fresh_provider_lookup` | Repaired. A changed unauthorized destination is refused before the disabled route provider can run, with no transmission. | Querying or sending an unauthorized final declaration. |
| Preparation | `borrowed_materialization_keeps_one_cumulative_admission_budget` | Repaired. Two complete packets fit the supplied cumulative budget, a third is refused, and a foreign cost cannot trigger lookup or restore admission. | Forking spend accounting during borrowed materialization. |
| Preparation | `changed_source_rebuilds_and_changed_mtu_fails_before_discovery` | Strengthened. Changed source appears in decoded wire bytes; reduced MTU fails before capture or send in either link mode. | Updating only packet metadata or reusing a packet that no longer fits. |
| Preparation | `interface_selectors_are_resolved_again_and_capture_identity_change_is_refused` | Repaired. A disappeared interface produces a named refusal, and a recreated interface produces the expected identity mismatch without sending. | Reusing the cached selector or silently changing capture identity. |
| Preparation | `cancellation_and_other_admission_costs_cannot_enter_reuse` | Repaired. Canceled and foreign-cost reuse retain their distinct errors and cannot reach the disabled route provider. | Looking up a route before checking control or admission ownership. |
| Preparation | `changed_wire_length_and_cumulative_budget_are_refused_before_discovery` | Repaired. Overspending is refused, changed wire length reports the admitted length, and a failed rebuild does not restore the spent budget or send a packet. | Reusing a cost for a different packet length or resetting spend on failure. |
| Multipath | `stable_flow_fields_checksums_and_stale_quote_rejection_all_strategies` | Strengthened. Flow fields and checksum invariants persist, valid quotes identify the expected responder and response kind, and old hop or sweep identities are rejected. | Retaining flow fields while losing the per-probe identity. |
| Multipath | `udp_short_quotes_are_attributed_only_with_an_exact_identity` | Strengthened. The supported short IPv4 quote reports its expected intermediate responder, while insufficient IPv6 and truncated quotes are refused. | Attributing a reply without enough quoted identity. |
| Multipath | `direct_echo_and_syn_ack_correlate_and_tcp_cleanup_has_correct_sequence` | Retained. Echo and SYN-ACK replies terminate the destination, and TCP cleanup uses RST with the reply acknowledgement as its sequence. | Ignoring direct replies or resetting with the wrong sequence. |
| Multipath | `tcp_cleanup_preserves_the_successful_probe_hop_limit` | Retained. Cleanup preserves each explicit hop limit across IPv4 and IPv6, including values above common defaults. | Sending cleanup with a default rather than the successful probe's hop limit. |
| Multipath | `sweeps_preserve_flow_identity_and_independent_termination_with_branch_and_rejoin` | Strengthened. Every expected flow/sweep completion has its proper terminal hop, and later batches preserve independent termination and adjacent topology. | Stopping both flows together or attributing a completion to the wrong sweep. |
| Multipath | `all_strategies_and_families_reach_destination_and_account_for_cleanup` | Strengthened. Both families and all strategies produce complete flow summaries, expected destination RTTs and correctly counted TCP cleanup traffic. | Empty summaries passing an all-elements assertion or omitting cleanup traffic. |
| Multipath | `gaps_ambiguity_and_retention_never_manufacture_edges` | Strengthened. Gaps and ambiguity preserve the independently expected adjacent edge, while omission and unknown ingress qualify completeness appropriately. | Manufacturing an edge through missing observations or dropping valid adjacent evidence. |
| Multipath | `unfinished_correlation_marks_the_batch_incomplete_before_building_topology` | Retained. Both correlation-expiry paths retain unmatched evidence and nodes, mark the affected hop incomplete and prevent edges through it. | Building topology from unfinished attribution. |
| Multipath | `invalid_flow_ranges_and_excess_probe_counts_are_rejected` | Strengthened. A valid request is accepted before invalid source-port ranges, flow counts and probe budgets are refused. | An always-refusing validator or an unchecked overflowing range. |
| Multipath | `authoritative_exchange_matching_blocks_a_stale_same_tuple_response` | Repaired. Generic matching emits a Response for the controlled stale tuple, while authoritative matching emits the exact frame as Unsolicited. | Recording stale evidence as an authoritative response. |
| Multipath | `cancellation_and_output_failure_stop_before_another_batch` | Strengthened. Cancellation or output failure ends with the expected error and only the actual initial pair of probes dispatched. | Starting another batch after the consumer stops. |
| Multipath | `topology_changes_require_two_observed_adjacent_sweeps` | Strengthened. A change reports the expected flow, hop, before/after responder, adjacent sweeps and evidence; a missing intermediate sweep prevents comparison. | Attributing a topology change across an observation gap. |
| Multipath | `non_echoing_udp_reply_is_not_attributed` | Retained. A reply with the right tuple but wrong echoed identity is refused in both families. | Accepting UDP tuple equality as complete identity. |
| Exchange | `every_matched_reply_refusal_qualifies_missing_observations` | Retained. Local refusal excludes ordinary unanswered inference and keeps quality incomplete even after a later positive reply settles the request. | Promoting a refused reply to evidence of silence. |
| Exchange | `clean_local_retention_does_not_promote_unknown_or_missing_ingress` | Repaired. Processing an actual frame without an ingress marker retains it as an unsolicited event and leaves observation quality unknown. | Assigning clean ingress merely because local retention succeeded. |
| Scan preparation | `scoped_and_unscoped_previews_obey_budget_and_materialize_every_probe` | Retained. Both preview paths obey small and metadata-sensitive budgets and materialize every expected destination, port and payload for scoped and unscoped targets. | Admitting oversized metadata or materializing the wrong target's packet. |
| Scan correlation | `unrelated_pending_ports_do_not_match_direct_or_quoted_replies` | Retained. Unrelated direct and quoted replies match nothing, while a known pending probe matches its independently expected index. | Treating a shared network tuple as the right port identity. |
| Scan correlation | `direct_and_quoted_supported_families_match_the_conservative_oracle` | Strengthened. Direct and full quoted families match the independently expected probe position; insufficient SCTP quotes match nothing. Differential checks remain supplementary. | Both match paths agreeing on an omitted or wrong candidate. |
| Scan correlation | `collisions_scopes_reuse_and_retirement_preserve_every_member` | Retained. Collisions keep each scoped member, retired identities disappear, reused identities remain reachable and duplicate insertion fails. | Collapsing collision members or crossing interface scopes. |
| Scan correlation | `custom_matcher_defaults_to_scoped_conservative_lookup` | Retained. A custom matcher retains the entire selected scope even when built-in tuple fields differ. | Applying built-in identity pruning to a custom matcher. |
| Scan correlation | `indexed_correlation_preserves_generation_freshness_deadlines_interfaces_and_late_replies` | Retained. Independent expected generation identity survives indexed lookup, while old ingress, wrong interface and expired pending state are refused. Retained late evidence remains reachable until eviction. | Selecting a stale generation or removing recent evidence too early. |
| Scan correlation | `ipv6_extension_ip_replies_and_truncated_or_bad_integrity_packets_use_the_same_oracle` | Strengthened. The extension-header reply has its known candidate, and accepted truncated prefixes independently match nothing. Corrupt integrity is also refused. | Shared oracle agreement on an invalid truncated response. |
| Scan correlation | `unknown_custom_decoded_identity_and_unrecognized_tunnels_use_conservative_fallback` | Repaired. Custom discriminators and unrecognized tunnels retain the expected candidates through actual lookup, without inspecting fallback storage. | Dropping a candidate whose decoder does not expose a built-in identity. |
| Scan correlation | `encapsulated_udp_probe_preserves_inner_matching_and_outer_quoted_identity` | Retained. An encapsulated response and outer short quote both identify the independently expected original probe. | Losing inner correlation or using inner fields for an outer quote. |
| Scan correlation | `retired_candidates_stop_matching_and_admission_recovers` | Strengthened. A full two-entry index refuses another insertion, retirement restores admission without disturbing the other scope, and repeated generations remain independently reachable then disappear. | Leaking admission, losing another scope or matching retired identities. |

# Remaining native I/O case audit

All 11 cases retain their owning suites. Thread cleanup uses destruction notifications and actual replacement work. TLS verification receives a fixed time through a private helper, preserving the public API. Only public CA and leaf certificates are checked in; the fixtures contain no private keys.

| Suite | Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- | --- |
| UDP | `retained_udp_response_limit_is_exact` | Strengthened. A controlled loopback server receives the exact request. Responses preserve the expected prefix bytes, sent-byte count, peer/local endpoint relationship and complete/truncated classification at both sides of the boundary. | Returning zero-filled bytes of the right length, reporting the wrong endpoint or misclassifying an exact fit. |
| Capture | `invalid_group_never_calls_injected_capture_provider` | Repaired. Invalid identity groups produce the specific group refusal and cannot activate the supplied provider. The provider fails immediately if called, rather than counting calls. | Reaching a capture provider before identity validation or returning an unrelated failure. |
| Capture | `incomplete_capture_identities_and_nul_are_rejected` | Strengthened. A valid request and group are accepted before testing missing names, zero indexes and NUL-bearing filters. Individual and grouped entry points retain their expected classifications. | Rejecting every request or skipping filter validation in one entry point. |
| Resolution | `native_resolver_retains_unique_addresses_in_first_seen_order` | Strengthened. Duplicate IPv4/IPv6 results do not consume retained capacity, first-seen order survives, and overflow reports the hostname-address limit classification and supplied hostname. | Reordering mixed-family results, charging duplicates or losing the failure classification. |
| Capture filter | `ecn_flags_are_numeric_symbols` | Strengthened. Numeric ECN symbols remain accepted. A symbolic hostname has the capture-filter refusal and identifies the supplied interface. No DNS or native filter compiler is called. | Treating supported numeric symbols as names or returning an unrelated error for a forbidden symbolic operand. |
| Route normalization | `scope_precedes_prefix_specificity` | Strengthened. Controlled documentation addresses establish that matching scope wins over a broader matching prefix, regardless of input ordering. | Choosing the first/last address rather than the configured ranking. |
| TLS trust | `ca_bundles_reject_every_other_pem_section` | Strengthened. The supplied CA validates the retained leaf at a fixed time. An unrelated CA, mismatched hostname and time before validity fail independently. Non-certificate-only and mixed PEM bundles remain refused. | Ignoring supplied anchors, disabling hostname checks, using wall time instead of the injected time or skipping foreign PEM labels. |
| Thread cleanup | `reservations_and_failed_transfers_keep_the_join_owner_until_actual_completion` | Repaired. Refused ownership transfer retains the owner's destruction notification and blocks admission until the thread finishes. A replacement join then completes with its expected result. | Releasing ownership after failed queue transfer or leaking the recovered slot. |
| Thread cleanup | `one_blocked_join_does_not_serialize_independent_cleanup_slots` | Repaired. Repeated independent joins finish while another join remains explicitly blocked. Both reserved slots are usable after release and complete their replacement work. | Serializing all cleanup behind one blocked thread or losing one slot permanently. |
| Thread cleanup | `dropping_last_cleanup_owner_retries_and_releases_worker_resources` | Renamed and repaired from `dropping_last_cleanup_owner_retries_a_failed_transfer_without_an_arc_cycle`. Last-owner drop retries a refused transfer, destroys the retained owner and allows the actual cleanup worker to exit, witnessed by its TLS destructor. | Leaving retained work or its cleanup worker alive after the last owner disappears. |
| Thread cleanup | `arbitrary_owner_drop_remains_charged_to_cleanup_after_the_thread_has_joined` | Repaired. An explicitly blocked owner destructor retains admission after join. Releasing it permits a new complete join with the expected owner result. | Freeing cleanup admission before an arbitrary owner destructor returns. |

# Security case audit

HTTP and indicator cases use controlled strings. Capture cases use injected events or generated packets with fixed timestamps. Protocol assumptions have dated references beside the assertions. These cases do not query remote services or the current wall clock.

| Suite | Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- | --- |
| Capture | `threshold_validation_reports_each_invalid_field_and_accepts_boundaries` | Retained. Invalid thresholds identify their field, constructor validation agrees, and legal boundaries validate. | Accepting nonfinite thresholds or skipping constructor validation. |
| Capture | `controlled_finalization_preserves_events_summary_and_completeness` | Strengthened. Independent subjects, evidence, measurements and completeness accompany agreement between finalization paths. | Losing or reordering findings in both paths. |
| Capture | `controlled_finalization_stops_on_sink_error_expiry_and_cancellation` | Repaired. A frozen clock isolates sink refusal, cancellation and explicit expiry. No later event reaches a refusing or cancelled sink. | Continuing delivery after the first failure. |
| Capture | `directly_constructed_hunt_documents_are_validated_and_normalized` | Repaired. Invalid documents are rejected and a mixed-case DNS observation emits the expected indicator identity and frame. | Bypassing validation of directly supplied documents. |
| Capture | `nanosecond_beacon_intervals_retain_precision_at_modern_epochs` | Repaired. Generated SYN packets at submicrosecond intervals produce the expected periodicity evidence and source frames through the analysis pipeline. | Subtracting epoch-sized floating-point times instead of durations. |
| Capture | `dns_checks_inner_labels_and_groups_by_following_domain_with_existing_budget` | Repaired. Findings name the independently expected suffixes and label counts. A constrained group budget refuses the extra groups. | Grouping only the first label or admitting beyond the budget. |
| Indicators | `ipv6_cidr_domain_boundaries_and_validation` | Retained. IPv6 and domain matches respect prefix and label boundaries, and invalid schema, fingerprints and duplicate identities are rejected. | Matching an adjacent prefix or a partial domain label. |
| Indicators | `domains_have_at_most_one_root_terminator` | Strengthened. A parsed rooted name matches independently expected candidates and a second root terminator is rejected. | Accepting repeated trailing dots or losing the parsed value. |
| Indicators | `cidr_prefixes_are_decimal_not_signed` | Strengthened. Signed prefixes are rejected and a parsed IPv6 zero-length prefix matches IPv6 addresses without matching IPv4. | Confusing address families or losing the prefix length. |
| Indicators | `blank_identifiers_are_not_useful_evidence_names` | Strengthened. Blank identities fail while meaningful identities and domain matching survive parsing. | Discarding a valid identity or accepting a blank one. |
| Indicators | `domain_matching_validates_candidate_labels` | Retained. Empty, oversized, NUL-containing and malformed labels cannot match a valid suffix. | Performing a raw suffix comparison on invalid names. |
| Indicators | `public_indicators_match_case_insensitively_without_normalization` | Retained. Directly constructed indicators keep case-insensitive, label-delimited matching and reject the root alone. | Requiring callers to pre-normalize public values. |
| HTTP assessment | `secure_headers_pass_and_cookie_values_never_escape` | Retained. Protective headers produce no findings and cookie secrets never enter the report. Cleartext does not demand HSTS. | Leaking cookie values or applying HSTS to insecure transport. |
| HTTP assessment | `referrer_fallback_and_wildcard_framing_are_not_overstated` | Retained. Unsafe referrer fallback and unrestricted framing each produce their finding. | Treating the first referrer token or a wildcard as protective. |
| HTTP assessment | `only_the_first_hsts_field_is_effective` | Retained with source. A later positive HSTS field cannot override the first zero lifetime. | Selecting a later field. |
| HTTP assessment | `cookie_attribute_whitespace_does_not_hide_protection` | Retained with source. Optional whitespace preserves protective cookie attributes without exposing values. | Comparing untrimmed attribute names. |
| HTTP assessment | `the_last_samesite_attribute_is_not_skipped_when_bare` | Retained with source. A trailing bare attribute does not leave an earlier protective value effective. | Ignoring the final SameSite attribute. |
| HSTS | `hsts_rejects_duplicate_directives_case_insensitively` | Retained with source. Duplicate names invalidate the field regardless of case. | Case-sensitive duplicate detection. |
| HSTS | `hsts_accepts_quoted_values_and_quoted_pairs` | Retained with source. Quoted digits and escaped characters remain valid. | Parsing only unquoted values. |
| HSTS | `hsts_accepts_optional_whitespace_around_equals` | Retained with source. Legal optional whitespace remains accepted. | Requiring adjacent directive names and values. |
| HSTS | `hsts_delta_seconds_are_digits_not_signed_integers` | Retained with source. Signed, fractional and zero values do not establish a positive policy. | Reusing a signed numeric parser or accepting zero. |
| HSTS | `hsts_positive_lifetime_need_not_fit_u64` | Retained with source. A valid positive decimal lifetime need not fit a machine integer. | Rejecting protection after numeric overflow. |
| HSTS | `malformed_extensions_invalidate_the_entire_hsts_field` | Retained with source. Invalid extension grammar invalidates the field while valid extensions remain accepted. | Ignoring malformed trailing directives. |
| CSP | `csp_directive_names_are_ascii_case_insensitive` | Retained with source. Mixed-case directive names retain their meaning. | Case-sensitive name matching. |
| CSP | `csp_uses_the_first_directive_in_each_policy` | Retained with source. First-directive precedence applies independently to each policy. | Choosing the last duplicate or merging separate policies. |
| CSP | `csp_does_not_treat_unicode_whitespace_as_a_separator` | Retained with source. Non-ASCII whitespace cannot create a directive boundary. | Using Unicode whitespace rules for protocol parsing. |

# Protocol message case audit

All 39 cases from `protocol/message/tests.rs`, `review_tests.rs` and `improvement_tests.rs` now belong to the four behavior suites under `protocol/message/tests/`. Their count is preserved. Reference vectors use the owned wire manifest and independent expected fields, with source URLs and check dates beside the vectors. Captures additionally check the fields explicitly supplied by the owned document fixtures, while permitting additional supported fields. Public byte ranges are tested by the bytes they select, rather than the storage order of range entries. No host network or wall clock is used.

| Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- |
| `truncated_and_unsupported_packets_preserve_bytes` | Strengthened. Invalid packets are rejected and unsupported text retains its complete bytes and consumed length. | Identifying opaque input while discarding its contents. |
| `mqtt_fields_are_editable` | Strengthened. Independent packet type, topic and payload expectations precede an edit. The rebuilt bytes have the expected new topic, length and unchanged payload. The wire assertion cites MQTT 3.1.1. | Updating a reflected field without updating the encoded packet. |
| `application_reference_vectors` | Strengthened. MQTT publish and connect, CoAP, AMQP heartbeat and preface, RESP, memcached and SSDP expose independent expected fields, preserve wire bytes and refuse an insufficient output budget. | An encoder and decoder sharing a field mapping error. |
| `protocol_expansion_reference_vectors` | Strengthened. Every listed protocol has independently expected fields from its wire vector, including nested records and network byte order. Encode budgets remain checked. | Swapping record members or decoding the wrong endianness while retaining round trips. |
| `ipv6_ospf_survives_authentication_header` | Strengthened. OSPF behind an authentication header retains explicit router, area, interface and interval fields without diagnostics. | Losing the network envelope or accepting a placeholder OSPF layer. |
| `coalesced_packet_messages_rebuild_without_losing_tail` | Strengthened. Two distinct MQTT messages produce independent wire contents and the expected ordered topics and payloads. | Duplicating the first message or losing the second payload. |
| `captures_convert_to_editable_documents_and_rebuild` | Strengthened. Each capture contains its owned wire vector, exports the promised fixture fields and rebuilds losslessly through JSON. | Exporting the wrong field while a matching encoder hides the error. |
| `noncanonical_ber_and_unknown_extensions_preserve_wire` | Strengthened. Unsupported BER remains opaque, and unknown CoAP/CDP records expose expected contents while preserving wire bytes. | Dropping an unknown extension or interpreting unsupported BER. |
| `reference_packet_prefixes_are_bounded` | Retained. Every accepted prefix reports consumed and payload ranges within the supplied bytes. Rejected prefixes cannot panic. | Reporting a range beyond a truncated input. |
| `sip_udp_without_content_length_uses_the_datagram` | Retained. A UDP SIP message without a length exposes the complete expected body and rebuilds without diagnostics. | Applying stream framing to a complete datagram. |
| `sip_tcp_still_requires_content_length` | Retained. A stream message without a declared boundary is refused. | Treating the current TCP segment as a complete SIP message. |
| `strict_build_checks_sip_and_rtsp_transport_framing` | Retained. Strict transport framing rejects missing lengths, while permissive output reports the expected diagnostic. | Silently accepting an unframed stream body. |
| `unsupported_stream_tail_survives_strict_rebuild` | Strengthened. A decoded MQTT ping retains the exact unsupported tail and rebuilds it. | Publishing two layer labels while dropping opaque bytes. |
| `datagram_messages_reject_unframed_opaque_tails` | Retained. Strict CoAP output rejects an unframed tail and permissive output reports it. | Treating arbitrary trailing bytes as another valid datagram message. |
| `folded_sip_and_rtsp_headers_preserve_bytes_and_frame_lengths` | Strengthened. Every split waits for the complete body, folded values retain their bytes, and injected header lines are refused. | Ending a frame at a folded header or permitting header injection. |
| `sip_udp_preserves_excess_bytes_after_declared_body` | Retained. Bytes after an empty declared body remain a distinct exact opaque tail and survive rebuilding. | Appending the tail to the body or dropping it. |
| `outer_ethernet_padding_does_not_extend_datagram_framing` | Retained. Padding belongs outside the IPv4 envelope and the complete padded frame is preserved. | Including Ethernet padding in CoAP framing. |
| `rtsp_and_sip_methods_accept_the_token_grammar` | Strengthened. Extended method tokens expose the expected start line and empty body, preserving exact wire bytes. | Rejecting an underscore or altering a method token. |
| `text_targets_and_content_lengths` | Strengthened. Valid length whitespace retains expected header bytes and body, while malformed targets and lengths are refused. | Trimming supported folding incorrectly or accepting a signed length. |
| `resp_framing_matches_canonical_decoder_and_depth` | Strengthened. Supported nested values equal independent typed trees and complete frame lengths. Unsupported numeric spellings retain exact opaque bytes. Depth and malformed-number refusals remain checked. | Two parsers agreeing on the wrong value, discarding unsupported bytes or allowing excessive nesting. |
| `dtls_document_rejects_oversized_fragment_offsets_without_panicking` | Retained. A document carrying an oversized fragment offset reaches a safe build refusal. | Truncating an offset or panicking during conversion. |
| `sflow_sample_members_support_editing_and_projection` | Retained. Published sample members resolve through schema paths, and a sampling-rate edit appears in the decoded projection. | Omitting a reflected member or losing the edited sampling rate. |
| `ipfix_and_dtls_nested_fields_support_editing_and_projection` | Retained. Nested schema paths remain addressable and edited values survive build, decode and projection. | Applying an edit to the wrong nested record. |
| `resp_payloads_support_typed_edits_filters_and_projection` | Retained. Scalar and nested typed edits appear in projections and matching filters, including wildcard arrays. | Ignoring a nested edit or comparing the wrong scalar type. |
| `interleaved_rtsp_layout_only_contains_binary_fields` | Strengthened. Independent binary wire bytes and decoded fields are checked. Named public ranges select the expected channel and body without depending on entry order. | Mistaking binary body delimiters for textual headers. |
| `resp_null_reflection_requires_canonical_empty_data` | Strengthened. Valid reflection creates the expected null variant, while nonempty or incorrectly typed null contents are refused. | Reporting success without applying a null edit. |
| `application_layouts_expose_exact_content_ranges` | Retained. SIP, RTSP, memcached, LDAP and CoAP ranges select independently expected bytes, including empty and long-form values. | Shifting offsets after variable-length headers. |
| `ospfv2_preserves_the_separate_authentication_digest` | Strengthened. Authentication header and digest fields retain their independently supplied contents, and the digest stays outside the declared packet length. | Conflating packet bytes and the authentication trailer. |
| `large_cdp_checksum_round_trips_without_overflow` | Strengthened. A large packet equals an independent complete wire expectation and known checksum, then exposes every TLV value. | A shared checksum overflow defect surviving a round trip. |
| `radius_padding_is_separate_from_attributes` | Retained. Consumed bytes stop at the declared packet boundary and the remaining padding survives rebuilding. | Treating padding as an attribute. |
| `ethernet_ip_errors_preserve_opaque_command_data` | Strengthened. Error replies expose their exact command, status and data for empty and nonempty payloads. | Parsing error data as a successful command structure. |
| `ipfix_options_template_withdrawals_round_trip` | Strengthened. Withdrawal records expose each expected template ID and empty field list, including complete options-template withdrawal. | Consuming an absent scope count or losing a withdrawal record. |
| `amqp_content_headers_require_complete_property_flags` | Strengthened. Valid headers produce exact independent packets and decoded payload fields, while incomplete flag chains fail both entry points. | Accepting a missing continuation word or ignoring a valid payload. |
| `bacnet_segment_ack_requires_its_window_size` | Strengthened. Every incomplete acknowledgement fails, while the complete acknowledgement produces exact bytes and decoded data. | Merely reporting success for a truncated or empty acknowledgement. |
| `other_slow_protocols_remain_opaque_before_lacp_length_checks` | Retained. Unsupported slow protocols preserve their bytes before LACP-specific validation. A truncated supported LACP packet is refused. | Rejecting unknown protocols under a LACP length rule. |
| `rtcp_reports_preserve_profile_extensions` | Strengthened. Single and compound reports expose expected packet types, counts, complete body bytes and extensions. Truncated reports fail. | Reordering compound reports or dropping profile extensions. |
| `mqtt_persistent_sessions_require_a_client_identifier` | Strengthened. Valid session combinations build exact independent wire bytes and expose the supplied flags, identifier and lifetime. Invalid combinations fail. | Accepting an anonymous persistent session or returning placeholder fields. |
| `mqtt_subscription_and_will_topics` | Strengthened. Valid subscriptions and will messages expose independent topic, packet and payload fields. Malformed wildcard placement is refused. | Accepting a valid packet but discarding its topic or will payload. |
| `malformed_resp_lines_and_modbus_ranges_are_refused` | Retained. A RESP line with an embedded carriage return and an excessive Modbus register quantity are refused. | Treating a forbidden line byte or out-of-range request as valid. |

# Python helper case audit

All 23 cases in `scripts/tests/test_script_support.py` are reviewed below. Files and permissions are controlled fixtures. Hash and reserved-name vectors cite primary sources and check dates beside their assertions. The file budget provider permits bounded reads and raises an I/O failure if the consumer exhausts its available bytes. The expected application behavior is a size refusal within that budget, without depending on a particular number of read calls. The default 32 MiB and 64-level boundaries are project-owned parser limits.

| Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- |
| `test_digest_rejects_non_regular_inputs` | Retained. A directory cannot be hashed as a file. | Omitting the regular-file check. |
| `test_digest_matches_sha256` | Strengthened. A cited independent vector and a larger input with distinct final bytes produce the expected SHA-256 digest. No chunk size is pinned. | Hashing only the first block or dropping the tail. |
| `test_digest_validation_requires_the_complete_lowercase_hex_value` | Added. Complete lowercase hexadecimal digests at supplied widths pass. Wrong lengths, characters, types and trailing data fail. | Accepting a matching prefix or ignoring the supplied digest width. |
| `test_supported_names_and_reserved_components_are_distinguished` | Added. Supported Unicode and ordinary names pass, while reserved components, separators and control bytes fail. | Rejecting ordinary spaces or permitting a device name with an extension. |
| `test_wide_json_values_preserve_every_item` | Repaired. All supplied items survive a wide document and a nonfinite final item is rejected. | Returning a truncated list or stopping validation early. |
| `test_json_reader_rejects_fifo_without_waiting_for_writer` | Retained. An actual named pipe is refused before opening it, with a bounded subprocess wait. | Blocking on a pipe instead of reporting a regular-file refusal. |
| `test_duplicate_keys_are_rejected_at_any_depth` | Retained. Root and nested duplicates fail. | Silently replacing an earlier object value. |
| `test_all_nonfinite_spellings_are_rejected` | Retained. Nonfinite tokens and numeric overflow fail. | Trusting the decoder's permissive number defaults. |
| `test_input_must_be_utf8_not_auto_detected_utf16` | Retained. UTF-16 and UTF-32 byte input cannot bypass the UTF-8 contract. | Passing bytes to an auto-detecting decoder. |
| `test_surrogates_in_additive_fields_and_keys_are_rejected` | Retained. Invalid surrogate strings and keys fail while a valid supplementary character survives. | Validating only fields consumed by a particular tool. |
| `test_depth_is_bounded_without_uncaught_recursion` | Strengthened. Complete object and list chains survive at the nesting boundary, while excess nesting fails safely. | Counting object and list depth differently, rejecting the boundary or silently increasing accepted depth. |
| `test_nested_siblings_are_validated_after_empty_containers` | Added. Expected nested siblings survive, while later invalid numbers or strings are refused after empty containers. | Ending traversal when the first nested iterator finishes. |
| `test_default_byte_budget_accepts_its_boundary_and_refuses_excess` | Added. A complete value fits the project byte ceiling and excess input is refused. | Changing the published default ceiling or accepting oversized bytes. |
| `test_size_is_measured_in_utf8_bytes` | Retained. A multibyte string fits its exact byte budget and fails below it. | Counting characters rather than encoded bytes. |
| `test_read_has_a_finite_limit` | Strengthened. Odd, even and minimum budgets accept complete boundary values, while oversized input with a valid prefix fails. | Reading too little or accepting a truncated valid prefix as a complete file. |
| `test_rejected_file_still_respects_the_available_read_budget` | Added. A bounded source yields a normal application size refusal without exhausting its available read credit. | Attempting to read substantially beyond the configured ceiling. |
| `test_invalid_json_limits_are_rejected_before_io` | Strengthened. Both text and file entry points reject invalid limits and accept the minimum positive limit. | Allowing zero, booleans or fractional limits through one entry point. |
| `test_prepare_report_removes_stale_success_but_not_input` | Retained. A stale report is removed, while alias refusal preserves the input. | Removing an input before checking aliases. |
| `test_success_creates_parents_and_utf8_newline` | Strengthened. A complete UTF-8 JSON value is published through multiple missing parent directories with a final portable newline. | Creating only the immediate parent or leaving invalid, truncated or platform-dependent report bytes. |
| `test_serialization_failure_preserves_existing_report` | Strengthened. Invalid numbers, keys and strings leave the previous report intact, including invalid nested siblings. | Replacing the previous report before validating all content. |
| `test_replacement_retains_the_existing_reports_permissions` | Added. A successful replacement preserves deliberately supplied POSIX permissions and publishes the complete new content. | Replacing a report with temporary-file permissions. |
| `test_replace_failure_cleans_temporary_file` | Retained. A controlled publication failure preserves the previous report and leaves no partial file. | Leaving an abandoned temporary report after failure. |
| `test_output_cannot_alias_input` | Strengthened. Same-path and hard-link aliases are refused, while a distinct output is accepted. Absent input paths and their normalized aliases are also refused. | Checking only existing file identity or comparing unnormalized path spellings. |

# Build metadata case audit

All 13 cases in `scripts/tests/test_build_manifest.py` are reviewed below. Version and compiler strings are supplied fixtures, and shell launchers quote the test interpreter path. No installed compiler or binary version is pinned. Required fields come from the independently supplied identity fixture rather than the validator's required-field list. The 64 KiB metadata ceiling is project policy. Release-asset cases are recorded in the enforcement table below, covering all eight cases in their owning file.

| Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- |
| `test_command_failures_have_a_clean_diagnostic_and_no_success_report` | Retained. Controlled binary or compiler failure produces exit one, a contextual diagnostic and no success artifact. | Publishing metadata after a failed identity command. |
| `test_write_and_verify_preserve_supplied_identity_and_detect_binary_changes` | Strengthened. Complete supplied identity is published and verified. Independent commit, target, feature, basename and version values on both sides of the expected value fail verification, as does changed binary content. | Replacing equality with an ordering comparison or ignoring a provenance field. |
| `test_version_and_compiler_payload_cannot_be_blank` | Retained. Prefix-only version and compiler fields are refused. | Treating a product name alone as identity. |
| `test_complete_provenance_is_required` | Strengthened. Every independently declared identity field is required and rejects blank or incorrectly typed values. | Removing a field from the implementation's required list or accepting a nonstring value. |
| `test_binary_digest_must_be_sha256` | Retained. A non-digest identity is refused. Detailed width and character cases belong to the shared helper. | Skipping digest validation at the metadata boundary. |
| `test_binary_name_is_not_an_archive_path` | Retained. Traversal, path separators, reserved components and malformed basenames fail metadata validation. | Allowing metadata to name an unsafe archive destination. |
| `test_compiler_identity_preserves_multiline_but_rejects_controls` | Retained with controlled strings. Normal multiline verbose output is accepted and forbidden controls fail. | Flattening legitimate compiler output or allowing hidden controls. |
| `test_version_is_an_unambiguous_product_line` | Retained. Wrong products, multiple lines and control-bearing version strings fail. | Accepting ambiguous executable identity. |
| `test_invalid_metadata_has_a_contextual_diagnostic` | Strengthened. Malformed and oversized metadata have contextual diagnostics. A complete identity at the exact byte ceiling loads unchanged. | Rejecting the valid boundary or accepting excess metadata. |
| `test_mode_is_required_before_binary_access` | Retained. Missing operation mode is refused before accessing the binary. The forbidden I/O interaction is the contract. | Hashing a binary before argument validation. |
| `test_invalid_release_inputs_do_not_execute_binary` | Strengthened. Invalid commit, target and feature identifiers are refused before an executable runs. Target and feature fields are also checked directly at the metadata boundary. | Executing unvalidated release input or accepting malformed portable identifiers. |
| `test_binary_mutation_during_version_query_is_rejected` | Strengthened. Different valid digests below and above the original digest after version lookup cannot establish identity. | Combining a version and digest from different binary contents or replacing equality with ordering. |
| `test_missing_binary_is_a_clean_failure` | Repaired. A missing file inside a controlled temporary directory produces exit one. | Depending on an unrelated absolute path being absent or returning the wrong exit status. |

# Forwarding consumer case audit

All 27 original cases and three added cases in `scripts/tests/test_forwarding_consumer.py` are reviewed below. Positive typed evidence is checked through public consumed reports and semantic identities. CLI cases use retained fixtures and assert output, diagnostics and exit status. Capture times and resource limits are controlled inputs. The consumer supports generic nonterminal events, so stream cases exercise its supported framing without claiming the producer currently emits progress records. These cases use no live networking or installed product version.

| Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- |
| `test_unmatched_and_unkeyed_census_preserves_retained_and_omitted_observations` | Retained. Both capture sides preserve nonempty retained and omitted unmatched/unkeyed observations. Contradictory totals, duplicate frames and malformed entries fail. | Losing a retained observation or accepting an omission count that does not account for the census. |
| `test_check_outcomes_require_the_declared_evidence_availability` | Retained. Independently specified state combinations determine which checks are evaluable and which outcomes are possible. | Calling unreadable evidence satisfied or refusing an available check as unevaluable. |
| `test_retained_checks_must_match_declarations` | Strengthened. Missing, additional or different checks identify the affected match and cause. An independent four-kind fixture preserves the complete checks and census. Matching empty fields in both declaration and retained check are refused. | Dropping a check kind, accepting a shared malformed field or diagnosing an additional check as missing. |
| `test_rule_budgets_include_every_declaration_and_utf8_literal` | Retained with a precise local type. Every rule category contributes to the configured count and UTF-8 byte budget, including an expectation literal and its separator. | Omitting a rule category or counting Unicode characters instead of bytes. |
| `test_capture_timestamps_preserve_the_full_signed_range` | Strengthened. Signed second extremes, nanosecond normalization and complete u32 link/interface bounds are preserved or refused correctly on either capture side. | Rejecting a valid large interface value or accepting the first value outside a published range. |
| `test_decoding_rejects_other_commands_and_preserves_additive_fields` | Strengthened. Additive data survives decoding, while another command, schema version or nonobject envelope is refused. | Accepting a nearby schema name through a lexical comparison. |
| `test_typed_evidence_validates_bounds_and_preserves_values` | Repaired. Full consumption preserves the supplied public typed keys, including IP, list and object values. Invalid types and bounds are refused through the public report boundary. Private canonical tuple assertions were removed. | Discarding a typed value or accepting booleans as integer evidence. |
| `test_json_envelopes_reject_ambiguous_and_invalid_input` | Retained. Duplicate keys, invalid UTF-8, surrogate text and nonfinite numbers cannot enter an accepted envelope. | Letting the last duplicate key silently win. |
| `test_presence_and_absence_outcomes_follow_readable_states` | Retained. Independent presence/absence truth tables accept the correct outcome and reject its opposite. | Treating two absent fields as a presence violation. |
| `test_stream_enforces_contiguous_sequence_terminal_and_exit_status` | Strengthened. A complete ordered multirecord consumer stream returns the expected terminal report. Gaps, duplicate or invalid ordinals, wrong envelope modes, unsupported formats, incomplete records and records after the terminal fail. Valid aggregate fixtures omit stream-only fields. | Advancing sequence by the wrong amount or reading a stream envelope as aggregate output. |
| `test_record_and_stream_limits_accept_the_boundary_and_reject_overflow` | Retained. Complete output fits an injected byte boundary and is refused one byte below the needed budget. | Using a strict comparison at the valid boundary. |
| `test_default_record_and_stream_budgets_preserve_complete_boundary_output` | Added. A complete aggregate at 16 MiB and a consumer stream at 64 MiB retain the exact report, while one additional byte fails. | Increasing or decreasing the project-owned default ceilings accidentally. |
| `test_oversized_input_is_refused_within_the_available_read_budget` | Added. Controlled sources provide finite read credit in either format. Oversized data produces the application refusal without exhausting the source's credit. Any number of reads is permitted within the credit. | Attempting to consume substantially more input than the configured refusal needs. |
| `test_retained_examples_remain_valid` | Strengthened. Every retained example returns the complete expected execution/domain result. Actual subprocess CLI calls check JSON output, stderr and exit status. An execution error with producer exit zero is refused with exit two. | Returning a success CLI exit for an execution error or silently accepting contradictory producer status. |
| `test_malformed_retained_evidence_is_rejected` | Strengthened. Malformed evidence includes null identity keys and floating-point or boolean capture and summary counters. Separate cases violate either keyed-rank bound and isolate ingress ordering. | Accepting noninteger counters, incomplete identities or weakened rank and ordering checks. |
| `test_identity_groups_are_unique_even_with_additive_wrapper_metadata` | Retained. Additional wrapper metadata cannot create another identity group for the same semantic value. | Comparing the entire wrapper instead of the declared typed identity. |
| `test_semantically_equal_identity_values_share_one_correspondence_group` | Renamed and strengthened from `test_object_identity_is_hashable_and_ignores_member_order`. Distinct object/list/IP identities remain separate, while reordered object members or equivalent IP spellings identify one group. List order remains meaningful. | Keeping duplicate semantic identities because their textual representation or member order differs. |
| `test_utf8_scalar_and_finite_numbers_apply_to_additive_fields` | Retained. Additive values and keys must still obey UTF-8 and finite-number rules. UTF-16 and UTF-32 bytes are refused. | Validating only metadata the consumer currently uses. |
| `test_explicit_depth_and_record_limits` | Strengthened. Both object and list chains at the nesting boundary decode unchanged, while the next nesting level fails. A separately constrained record is refused. | Counting object and list depth differently or rejecting the valid boundary. |
| `test_additive_metadata_and_pre_epoch_timestamp` | Strengthened. Additive metadata and the pre-epoch timestamp preserve the exact result. Valid incomplete observations on either side retain diagnostics and can coexist with a larger capture census. Understated incompleteness fails. | Dropping diagnostics or requiring a retained count to equal the full capture census. |
| `test_retained_outcomes_cannot_exceed_the_published_summary` | Added. Valid fail/inconclusive reports are accepted. Independently understating satisfied, violated or unevaluable counts fails even when aggregate totals, omitted violations and verdict remain otherwise consistent. | Starting a retained-outcome count below zero or omitting retained classifications. |
| `test_invalid_exit_codes` | Retained. Boolean, negative and floating-point process statuses are refused. | Treating a boolean or fractional value as a process exit code. |
| `test_nonterminal_error_cannot_precede_success` | Retained. A nonterminal event with execution-error status cannot be followed by success. | Ignoring an earlier execution failure when a later terminal record succeeds. |
| `test_every_check_kind_validates_its_typed_operands` | Retained. Every non-preserve check kind refuses invalid typed operands. Other cases cover preservation. | Skipping operand validation in one check-kind branch. |
| `test_observed_and_absent_states_agree_with_values` | Retained. Observed cells require values and absent cells cannot carry them. | Accepting a state label that contradicts its evidence. |
| `test_evaluable_checks_cannot_be_marked_unevaluable` | Retained. Readable evidence cannot be marked unevaluable. A partial state may retain an attached value. | Ignoring evaluable evidence or discarding legitimate partial information. |
| `test_expectations_do_not_invent_ingress_states` | Retained. An expectation cannot invent an ingress state. | Treating an expectation like a preservation comparison. |
| `test_visible_reordering_with_omitted_pairs` | Strengthened. Visible inversion flags and conservative omitted-pair bounds remain checked. A large bounded-detail report preserves a 300-pair census with unselected input and omitted matches. | Confusing integer identity with numeric equality or requiring retained details to equal the complete census. |
| `test_violation_evidence_is_not_an_unchecked_side_channel` | Strengthened. All four check kinds have independently constructed valid contradiction evidence. Expectations cover unmatched egress observations with no ingress/key. Undeclared, equal, invalid-frame, invalid-key and invented/missing operand evidence fails. | Accepting a presence violation with equal presence or allowing an expectation violation to invent an ingress operand. |
| `test_ambiguous_group_and_omission_census` | Strengthened. Complete, partially retained and wholly omitted ambiguous groups preserve their public census. A four-member case exercises retained/omitted addition. An omitted group lacking budget on one side is refused. | Using bitwise combination for member totals or allowing a hidden group with no remaining ingress observation. |

# Verified seed and receiver case audit

The direct Linux/all seed stage, receiver execution and workflow are connected. The following cases validate their observable evidence and refusal behavior. These checks do not establish production mutation scores or weekly throughput.

| Case | Protected behavior | Representative defect |
| --- | --- | --- |
| `test_completed_weak_seed_reuses_only_actual_kills` | A complete 25-percent seed remains usable, including a target language read from JSON. Only actual kills are reused. Nonkills remain executable, the partition is disjoint and complete, and donor identity/digest metadata is retained. | Comparing language strings by object identity, requiring a strong seed score, reusing nonkills or dropping donor provenance. |
| `test_removed_seed_ids_and_new_receiver_ids_preserve_receiver_order` | IDs absent from the receiver are ignored, new IDs execute, and empty/all-reused receivers remain valid. A thousand distinct new identities preserve their order. | Reusing by approximate identity, comparing counts by object identity or adding donor-only work to the receiver. |
| `test_empty_completed_seed_never_invents_a_kill` | A valid empty seed leaves every receiver ID executable. | Inferring reuse from group membership without an actual kill. |
| `test_original_receipt_bytes_are_bound_by_the_donor_digest` | Semantically equal receipts with different bytes retain their own digests. | Hashing a reconstructed report instead of the supplied artifact. |
| `test_schema_context_workspace_and_shards_must_be_direct_and_complete` | Wrong schema/context, unsupported shards, false or nonboolean workspace flags and missing fields fail. Mismatched schema/profile values on either side of the supported value and zero shard counts are refused. | Treating a noncanonical or incomplete context as the direct seed. |
| `test_every_target_component_and_report_binding_must_match` | All Target fields and Report group/reason/source/tool bindings are checked, including both lower and higher mismatched values. | Reusing a partial-file seed for a full target or another revision/tool, or accepting one direction of a mismatch. |
| `test_expected_source_identity_requires_complete_lowercase_digests` | Short or noncanonical source identities fail even when the receipt exactly agrees with the invalid input. Full SHA-1 and SHA-256 Git revisions remain supported with a SHA-256 source fingerprint. | Accepting an ambiguous revision prefix or rejecting a malformed fixture only because another field differs. |
| `test_matching_python_seed_is_outside_the_supported_reuse_scope` | Even otherwise matching Python metadata is refused in this Rust-only phase. | Permitting an unsupported language because its fields happen to match. |
| `test_missing_duplicate_and_unfinished_outcomes_cannot_supply_reuse` | Failed baseline, incomplete run, duplicate inventory/results and missing/extra results fail. | Accepting only the completed subset of a seed. |
| `test_transitive_or_exclusion_proofs_are_rejected_at_every_level` | Receipt, Report and Outcome additions cannot carry reuse chains or exclusion claims. | Treating an inherited kill as direct execution evidence. |
| `test_malformed_receipts_fail_instead_of_supplying_a_plan` | Bad JSON, UTF-8, duplicate JSON keys, wrong flags, unknown statuses and missing evidence fail. | Silently accepting an overwritten or malformed proof. |
| `test_invalid_receiver_inventory_is_not_silently_deduplicated` | Duplicate, blank and scalar-string receiver inventories fail. | Hiding missing receiver work through set coercion. |
| `test_direct_report_accepts_partial_shards_without_making_them_complete_seeds` | Direct parsing preserves valid partial shard data while complete-seed validation still refuses an unfinished inventory. | Treating a partial actual run as a complete donor. |
| `test_direct_report_refuses_reuse_or_exclusion_claims_before_normalization` | Unknown reuse, donor and exclusion fields are refused in raw reports and outcomes. | Erasing an inherited-proof claim while normalizing it into a direct outcome. |
| `test_seed_proofs_require_complete_direct_workspace_execution` | Seed finalization requires every shard, direct raw fields, successful workspace evidence and exact scope/source/tool binding. A complete weak donor is accepted. | Borrowing from incomplete shards or discarding unsupported proof fields before validation. |
| `test_seed_command_publishes_only_complete_workspace_evidence` | The actual CLI publishes a seed that its strict parser accepts and removes a stale seed when later validation fails. | Leaving an old successful proof behind after a failed generation. |
| `test_coverage_digest_binds_values_and_ignores_object_key_order` | An independently encoded UTF-8 SHA-256 vector fixes the coverage digest. Object key order is irrelevant, while inventory order, reused identities and seed bytes affect the digest. | Returning a constant digest or hashing a different serialization. |
| `test_receiver_coverage_binds_actual_partition_and_exact_seed_bytes` | Reordered shard input preserves the exact executable and reused identities and seed digest. A differently encoded seed is refused. | Trusting a receiver partition without matching the supplied seed. |
| `test_receiver_requires_one_coverage_record_and_own_successful_baselines` | Even an all-reused receiver needs exactly one coverage record, consistent shard digests, successful own workspace baselines and supported raw fields. Both lower and higher mismatched digests fail. | Treating empty execution as permission to omit evidence or allowing one direction of a digest mismatch. |
| `test_recomputed_digest_cannot_turn_non_kills_into_reused_coverage` | A recomputed digest cannot authorize missing or false reuse, duplicate inventory, extra or omitted executable identities, changed seed bytes or unsupported proof fields. | Checking only the hash and accepting a false coverage claim. |
| `test_seed_receiver_executes_remaining_and_new_ids_with_direct_coverage` | The CLI executes seed survivors, timeouts and new receiver identities while reusing exact kills. Its score combines actual outcomes and publishes per-context counts. Unrelated previous output cannot exclude a new identity. | Copying old SDK exclusions, filtering by a prefix or synthesizing receiver kills. |
| `test_receiver_refuses_stale_seeds_and_missing_coverage_or_shards` | Reordered canonical shard files pass. Modified canonical status or evidence, missing canonical or receiver shards, absent or tampered coverage, omitted executable identities and stale seeds fail. | Accepting an embedded seed without its actual submitted execution or trusting a recomputed false partition. |
| `test_all_reused_receiver_still_requires_its_workspace_baseline` | Empty receiver execution is reported without fabricated outcomes, but a failing own baseline prevents a completed report. | Borrowing seed health when a receiver's feature configuration is broken. |

# Seed reuse functionality evidence

A committed, dependency-free two-crate fixture exercised the installed cargo-mutants 27.1.0 binary. The all-features seed killed three of four mutations. The portable receiver reused those exact three kills, executed the remaining survivor and killed it. Its raw SDK report and normalized outcomes contain only the one executed mutation. This is a fixture demonstration, not a production mutation score.

From the retained fixture directory, this command displayed the verified result.

```sh
cd /tmp/pcr-seed-real-sdk-fixtures-p5nc3x4z/survivor-receiver
python3 scripts/run_mutation.py check --plan artifacts/plan.json --language rust --shards 1 --output artifacts --platforms ubuntu-24.04 --profiles all portable --seed artifacts/all/seed | jq '{killed,eligible,status,execution_contexts: [.execution_contexts[] | {profile,executed,reused}]}'
```

```json
{
  "killed": 4,
  "eligible": 4,
  "status": "passed",
  "execution_contexts": [
    {
      "profile": "all",
      "executed": 4,
      "reused": 0
    },
    {
      "profile": "portable",
      "executed": 1,
      "reused": 3
    }
  ]
}
```

A second fixture killed all four mutations in the seed. Its selected crate's portable tests passed, but a dependent crate had a failing portable test. Even with no mutations left to execute, the receiver returned exit one for this command.

```sh
cd /tmp/pcr-seed-real-sdk-fixtures-p5nc3x4z/empty-receiver-failing-test
python3 scripts/run_mutation.py run --plan artifacts/plan.json --language rust --shards 1 --profile portable --platform-label ubuntu-24.04 --output artifacts/portable --seed artifacts/all/seed
```

```text
Mutation audit failed. sample failed. Rust workspace baseline failed
```

The retained baseline log shows the dependent test's actual value of 13 against its deliberately incorrect expectation of 99. Both SDK discovery lists are empty, and no mutation execution report is published. Removing either context's receipt from the healthy fixture also makes the final check fail. Restoring both receipts makes it pass.

# Audit workflow survivor repairs

The following cases address behavioral gaps identified in authentic older Rust mutation output for `audit.rs`. The source-to-test mapping targets 40 of 41 observed survivors; this is not a remeasured score. A complete in-memory TLS session now checks the HTTPS application-write gate, and one zero-byte authorization comparison remains a candidate for individual equivalence review.

| Case | Protected behavior and representative defect | Controlled setup and assertions |
| --- | --- | --- |
| `audit_validation_refuses_invalid_requests_before_connecting` | Invalid TLS limits, server names, ports and timeout bounds, plus invalid HTTP hosts, paths and response limits, must fail before connection. Deleting validation or an individual disjunct admits one of these requests. | An injected TCP provider panics if used. Invalid cases independently vary one field. Assertions require the intended public error and no transmitted bytes. |
| `audit_http_writes_one_head_and_uses_the_final_response` | Send exactly the configured HEAD request and report the final response after informational headers. Empty or incorrect request construction, early response selection, missing redaction or extra reading must fail. | Scripted 100, 103 and 200 responses include different cookies. The stream fails on further reads. Assertions independently specify request bytes, final status, host, path, completeness, no security findings, cookie flags, redaction and public byte measurements. HTTP wire syntax is sourced beside the expected request. |
| `audit_http_accepts_request_and_response_boundaries` | The maximum accepted timeout, host, path and response sizes remain usable. Exact final-response capacity succeeds while one byte less is incomplete. Status 101 is a final response. Off-by-one request guards, truncation acceptance and treating 101 as informational must fail. | Fixed response bytes and a fake clock. Assertions inspect the actual outbound request and specific report or error results. |
| `audit_policy_and_peer_refusals_precede_request_bytes` | A spent parent deadline, insufficient packet or byte allowance, disallowed destination, or substituted connected peer must prevent request transmission. Removing authorization or peer comparison must fail. | Injected provider refuses calls for pre-connect policy failures. It exposes a controlled peer for the post-connect checks. Both HTTP and TLS paths require rejection with zero transmitted bytes. |
| `audit_http_retains_distinct_io_and_control_failures` | Preserve read and flush I/O failures, cancellation, expiration and exact-deadline timeout. Reject empty, informational-only, incomplete, malformed and request-shaped responses. Deleting the failed-outcome or timeout-outcome arm must fail. | Scripted errors, a monotonic fake clock and injected cancellation. The timeout-boundary case advances to exactly five seconds, where a zero remaining socket budget is refused even though completed-work enforcement permits equality. No sleeps or scheduler timing determine results. |
| `audit_tls_does_not_publish_a_report_after_handshake_eof` | A peer closing before the TLS handshake finishes must return an EOF error instead of an audit report. | The real TLS client runs over the injected empty stream. Assertions require `UnexpectedEof` and evidence that TLS handshake bytes were actually transmitted, without pinning their contents or count. |
| `tls_report_retains_observations_when_certificate_retention_is_truncated` | A completed handshake with intentionally unretained certificate evidence preserves observed protocol, cipher, endpoint and byte measurements, emits incomplete chain/name findings, and reports only the truncation reason. Reversing either finding selection or handshake completeness must fail. | A valid zero-certificate-retention configuration and supplied completed-handshake evidence. Assertions check visible report content. Finding order is normalized. No live certificate or current validity date is consulted. |
| `audit_https_withholds_request_when_certificate_evidence_is_unavailable` | A real completed TLS session reports unavailable verification and withholds all HTTP application bytes. Reversing the verification gate sends a request and fails the test. | A rustls server and client exchange in-memory records with an ephemeral generated key. Certificate retention is disabled, and the peer captures decrypted application bytes. No stored key, current-time validity assumption, specific cipher or handshake write count is used. |

# Mutation progress

The first complete audit of `scripts/mutation_reuse.py` at commit `0623eabb9f2655fffadef1a3e525c64fae4ee217` measured 197 kills from 221 eligible mutants, or 89.1 percent, with ten compilation-invalid mutants and no exclusions. Survivors exposed one-sided mismatch fixtures, incomplete source-identity validation fixtures and missing coverage for large inventories. Existing mapped cases now cover those behaviors. The full measurement must be repeated on the final source before claiming a passing score.

The first completed exploratory forwarding run measured the source snapshot at commit `6c8698caf40c0f9c2503b867bed3b4b6f002cb51` with tree digest `6c70734e2ff5a05b24e9dc94666b84c6809a7d27bea257e04126f5589bd1129f`. It killed 1,172 of 1,765 eligible mutants, a score of 66.4 percent. Twenty compilation-invalid mutants were excluded. There were 592 survivors and one timeout, with no equivalent exclusions. This older snapshot does not establish the score of the current branch.

Survivors exposed missing cases for nonempty unmatched and unkeyed capture counts, omitted matches and evidence availability. Added cases now check retained and omitted observations on both sides, conservative reorder bounds, and valid or contradictory outcomes across evidence states. Targeted Cosmic Ray reruns killed four previously surviving arithmetic mutants in rule budgeting, omission accounting and capture totals. A complete rerun is still required before claiming any new module score.

The exploratory build-manifest run attempted all 176 mutations but produced a worker exception when Cosmic Ray tried to replace a qualified exception name inside a tuple. No score was accepted for that run. Importing the exception by name makes the mutation executable in both affected tools. Targeted reruns completed normally and killed both handler mutations. CLI regression cases also verify that failed binary, compiler and version-control commands return a failure diagnostic without publishing a success report or plan. No mutation was excluded to address the runner error.

At commit `6aa54f149b817ca7a539cbaa5618577a6d659d6b`, the release-assets rerun killed all 126 mutants, with no exclusions, survivors or timeouts. The same snapshot measured 426 of 484 eligible kills for results and 138 of 162 for selection. Those two groups remain below the threshold. Subsequent source-provenance repairs require fresh results before any current-tip score can be claimed.

The exploratory Python run completed every generated work item. It also measured 313 kills out of 458 eligible mutants for the result checker, 77 out of 156 for selection, 114 out of 126 for release assets, and 171 out of 258 for shared script support. The release-assets score exceeds the threshold, but its twelve survivors still exposed missing schema, canonical-path and byte-budget cases. Those cases have been added. Checker cases now cover all outcome classes, malformed artifacts, baseline execution, scoped exclusions and both failure counters. Complete module reruns are required to measure these repairs.

# Enforcement case audit

The following later repairs retain the original scope-binding and baseline cases and exercise complete CLI results against distinct controlled Rust and Python tool versions.

| Case | Change and protected behavior | Representative defect |
| --- | --- | --- |
| `test_published_scores_preserve_fractional_percentages_and_evidence_counts` | Added. Captures the published JSON score for a controlled 20-kill, one-survivor, one-timeout and two-invalid fixture. It checks the fractional percentage, all category counts, surviving/timed-out identities and measured tool version. | Publishing a truncated percentage, dropping timeout denominator entries or reporting incorrect counts/version evidence. |
| `test_all_shards_must_agree_and_complete_the_inventory` | Strengthened. Existing complete, omitted and duplicate shards remain covered. Out-of-range or zero IDs, incorrect shard totals, a changed discovered inventory, false baseline and incomplete flags now fail independently. | Accepting a collection solely because it has the expected number of files, or ignoring one shard's extra discovered mutant. |
| `test_cli_selects_owned_targets_and_runs_with_default_output_paths` | Added. Actual CLI calls select a complete controlled workspace, publish its plan and measure both Rust targets under the default Rust output path. A committed Python-only change then selects exactly that module and runs/checks under the default Python output path. | Returning an empty successful selection, losing selected files, dispatching the wrong language or using the wrong default output directory. |
| `test_completed_survivors_and_timeouts_fail_the_cli_gate` | Added. Completed Rust and Python survivor reports publish valid measurements but fail the policy check. A completed cargo-mutants exit-three fixture records one timeout and two kills, keeps all three eligible and also fails the check. | Rejecting a valid timeout report as a runner error, counting timeout as a kill, dropping it from the denominator or returning success for a completed weak score. |
| `test_invalid_shards_and_wrong_tool_versions_are_refused_before_execution` | Strengthened. Existing invalid bounds and unequal-version cases remain. The other language's controlled tool version is explicitly rejected. Expected-version diagnostics now name the language-specific fixture version. | Selecting a Rust version for a Python tool or accepting the wrong tool's version. |
| `test_each_selected_target_receives_the_original_source_snapshot` | Strengthened. Existing independent-target and original-source assertions remain. Every resulting Rust report must retain the controlled Rust tool version. | Publishing a version from another language while the work itself succeeds. |
| `test_rust_tool_reports_cover_build_scripts_features_and_disposable_source` | Strengthened. Existing five-profile, build-script, counts and source-preservation assertions remain. Reports retain the controlled Rust version. | Losing language-specific provenance during report creation. |
| `test_python_tool_handles_an_interpreter_path_with_spaces` | Strengthened. Existing complete execution, policy check and source preservation remain. The report retains the distinct Python version. | Reusing Rust tool metadata for a successful Python run. |

`test_artifacts_cannot_replace_a_full_or_different_file_selection` additionally checks complete target binding. A narrow-file report cannot satisfy a full crate, a different narrow file set, a different selection reason, a wrong-language target or duplicate requested groups. The snapshot case checks a configuration file that sorts before the exclusion policy and an absent tracked file before a retained source, with independent digests for each content change.

`test_platform_and_profile_cohorts_combine_only_their_own_shards` supplies two platforms, two profiles and two shards, with a different independently detected mutation in each platform/profile pair. The complete matrix combines all four kills. An extra artifact with only a foreign platform or profile is refused. This checks actual matrix selection rather than inferring it from isolated profile runs.

The original combined mutation cases now live in the owning suites listed above. SDK execution cases use controlled tool reports and scratch checkouts. They check public commands, artifacts and admission of complete results. A separate real Cosmic Ray run below validates the interpreter-path regression against the pinned SDK.

| Case | Disposition and protected behavior | Representative defect |
| --- | --- | --- |
| `test_outcome_counts_and_evidenced_exclusions_keep_their_own_groups` | Added. Every outcome category is reported, and reviewed equivalents affect only their exact group and revision. | Applying an exclusion to another group or treating a timeout as invalid. |
| `test_artifact_parser_preserves_false_completion_and_rejects_invalid_values` | Added. Valid JSON artifacts are scored, explicit incomplete flags remain incomplete, and malformed fields fail validation. | Converting false or nonboolean completion into success. |
| `test_cosmic_ray_classifies_failures_errors_and_invalid_syntax_independently` | Added. Either failure counter can establish a kill. Syntax-invalid mutations are separate, and contradictory or malformed evidence fails. | Cancelling equal failure and error counts or trusting an unsupported outcome. |
| `test_rust_survival_timeout_and_compilation_failure_are_distinct` | Added. Executed tests, timeout evidence and compiler diagnostics map to distinct outcomes. Mismatched phases and exits fail. | Counting compilation failure or timeout as a kill. |
| `test_rust_baseline_requires_successful_test_execution` | Added. A baseline needs a successful test phase and cannot contain failed earlier phases. | Accepting a successful build without running tests. |
| `test_production_changes_select_their_files_without_unrelated_groups` | Added. Independent production changes select only their files and modules. | Mutating the wrong crate or losing a changed production file. |
| `test_adding_inline_tests_expands_selection_to_their_complete_crate` | Added regression. Adding or removing inline tests selects their entire crate, with or without a test-only module. | Selecting only the edited file for a newly added inline test. |
| `test_shared_changes_select_complete_owned_language_groups` | Added. Fixtures, dependencies and shared support select the independently expected groups, while owned tests select their modules. | Skipping a language or unrelatedly narrowing a shared change. |
| `test_malformed_ownership_cannot_silently_remove_production_modules` | Added regression. Malformed or blank mappings and unowned source files fail selection. | Accepting an empty test destination as ownership. |
| `test_inventory_shape_is_explicit` | Strengthened. Complete manifests with unsupported schemas, empty lists and invalid entry types are rejected. | Accepting a different schema when other fields are valid. |
| `test_paths_are_safe_portable_and_canonical` | Strengthened. Trailing separators join the existing unsafe and noncanonical path cases. | Accepting a directory-like path after canonicalization. |
| `test_all_protocol_fixture_references_exist_and_are_packaged` | Repaired. Controlled files and package entries must both contain every referenced fixture. | Checking only disk existence or only the package list. |
| `test_protocol_fixture_manifest_enforces_its_byte_budget` | Added. A fixture manifest fits at the project byte ceiling and is refused one byte above it. | Raising, lowering or bypassing the read ceiling. |
| `test_loaded_release_inventory_is_bounded_and_exports_supplied_assets` | Added. A fresh module import exports the supplied inventory at the byte boundary and fails above it. | Applying the ceiling only to protocol fixtures. |
| `test_threshold_is_strict_and_applies_to_every_group` | Retained. Exactly 90 percent fails, a score above it passes, and a weak group cannot borrow another group's kills. | Applying an aggregate score or an inclusive threshold. |
| `test_missing_duplicate_and_unfinished_results_fail_closed` | Retained. Missing, duplicate and unfinished results or absent provenance cannot produce a score. | Accepting a partial inventory. |
| `test_timeouts_stay_in_the_denominator` | Retained. Timeout identities remain eligible and never increase the kill count. | Counting a timed-out run as a detected defect. |
| `test_only_evidenced_equivalents_and_invalid_compilations_are_excluded` | Retained. Exact evidenced equivalents and compiler-invalid mutations are the only supported exclusions. | Excluding an unknown, already-killed or unexplained mutant. |
| `test_cli_rejects_cached_results_after_uncommitted_source_changes` | Added regression. Matching source can be scored, while changed source and artifact directories mixed with measured inputs are rejected. | Trusting a matching commit after the tests change. |
| `test_reviewed_exclusions_can_be_committed_without_referring_to_their_own_hash` | Added regression. A reviewed equivalent can be committed and scored against the same source. Applied evidence appears in the score artifact. | Making a review depend on the hash that changes when that review is committed. |
| `test_empty_selection_is_reported_with_its_reason` | Strengthened. Zero eligible mutations produce a not-applicable artifact with the selection reason and no numeric percentage. | Treating an empty group as measured coverage. |
| `test_all_shards_must_agree_and_complete_the_inventory` | Retained. Complete disjoint shards combine, while absent or repeated shards fail. | Passing an unfinished shard collection. |
| `test_reports_from_another_revision_or_tool_cannot_pass` | Retained. Old commits and mismatched tool versions cannot satisfy the gate. | Using stale evidence after a change. |
| `test_required_feature_runs_can_detect_different_mutants` | Strengthened. Complete runs can detect complementary defects, while incomplete or inconsistent source runs cannot combine. | Filling missing work with results from another profile. |
| `test_cli_reports_external_command_failure_without_a_success_plan` | Retained. A controlled failing version-control command produces a failure diagnostic and no plan. | Publishing a plan after command failure. |
| `test_cosmic_ray_requires_actual_completed_test_results` | Retained. Worker completion, consistent test evidence and timeout classification are required. | Trusting a tool's kill label after a worker crash. |
| `test_python_mutant_identity_survives_a_new_session` | Strengthened. Identities are stable across sessions and distinguish source spans, operators and arguments. Malformed spans are rejected. | Applying an exclusion to the wrong mutation after a rerun. |
| `test_rust_inventory_and_baseline_are_required` | Retained. Completed inventory and baseline evidence accompany actual test execution. Infrastructure failures are not compiler exclusions. | Accepting a tool crash as an invalid mutant. |
| `test_committed_additions_deletions_and_renames_schedule_their_owners` | Strengthened. Real local commits add source, delete tests, delete production modules and rename modules with ownership updates. All surviving affected owners are selected. Git configuration is isolated. | Rejecting a legitimate removed module or losing either side of a rename. |
| `test_deleted_tests_select_their_production_owners` | Retained. Deleted separate and inline tests select the expected crate or Python module. | Filtering only production-file additions. |
| `test_shared_inputs_schedule_every_affected_language` | Retained. Actual repository configuration and shared fixtures select every affected group. | Omitting a group from shared-input scheduling. |
| `test_unmapped_python_files_cannot_bypass_mutation_checks` | Retained. A new Python source without ownership is rejected. | Silently ignoring a new source location. |
| `test_documentation_only_change_has_no_mutants` | Retained. A general documentation edit does not schedule unrelated mutations. | Treating every repository edit as production scope. |
| `test_disposable_snapshot_includes_working_changes` | Retained. Tracked edits and new source files reach the disposable snapshot and alter its digest. Git configuration is isolated. | Measuring committed content while testing a changed worktree. |
| `test_repository_inventory_is_valid` | Strengthened. Repository metadata validates and exported asset sequences agree with its contents. | Exporting a truncated or wrong inventory. |
| `test_duplicates_and_source_generated_collisions_are_rejected` | Retained. Duplicate files across either inventory are rejected. | Allowing a generated file to overwrite a source asset. |
| `test_device_components_and_ancestor_collisions_are_rejected` | Retained. Device names and case-insensitive file/directory collisions cannot enter an archive. | Producing an archive that cannot be extracted safely on a supported platform. |
| `test_cosmic_baseline_requires_successful_unmutated_test_evidence` | Added. Exactly one completed, unmutated baseline must contain successful nonempty test execution. | Trusting an incompetent SDK baseline or accepting mutated, missing or failing baseline results. |
| `test_each_selected_target_receives_the_original_source_snapshot` | Added. Two crates run from independent copies of one source snapshot, produce separate scores and preserve the original checkout. | Reusing the first crate's modified source for the second crate or mixing language scopes. |
| `test_invalid_shards_and_wrong_tool_versions_are_refused_before_execution` | Added. Invalid shard bounds and either unequal tool version fail before source execution. | Running an unintended shard or accepting an unpinned SDK. |
| `test_runner_mutations_use_an_immutable_bootstrap` | Added. Syntax mutations to the harness remain compilation-invalid and preserve the user's source. | Allowing a mutated harness to invent or omit its own evidence. |
| `test_rust_tool_reports_cover_build_scripts_features_and_disposable_source` | Added. Every configured profile measures the controlled Rust files and build script, retaining complete scores and unchanged original manifests. | Omitting a feature flag or build script, or modifying the original checkout. |
| `test_python_tool_handles_an_interpreter_path_with_spaces` | Added regression. The CLI completes and scores a Python measurement when executable and artifact paths contain spaces. | Splitting the interpreter path into separate command arguments. |
| `test_external_failures_never_publish_a_completed_measurement` | Added. Discovery, baseline, execution and export failures for either SDK leave no accepted report, including a zero-exit incompetent Python baseline. | Publishing success after a worker, command or baseline fails. |
| `test_scoped_shards_combine_once_and_omissions_fail_the_gate` | Added. The CLI measures the selected files across disjoint shards, then rejects a missing shard. | Ignoring file selection, duplicating work or accepting a partial run. |
| `test_empty_discovery_runs_a_baseline_and_preserves_the_selection_reason` | Added. Both SDKs validate an empty selection and report not applicable with its reason. | Treating absent discovery as coverage or skipping the baseline. |
| `test_selected_module_runs_its_owned_tests_without_unrelated_failures` | Added. The harness runs the selected module's suite without importing unrelated failing tests. | Discovering unrelated suites in a scoped measurement. |
| `test_every_mapped_suite_contributes_to_failure_evidence` | Added. Both declared suites contribute their actual test and failure counts. | Dropping an additional test owner from discovery. |
| `test_runtime_test_errors_are_distinct_from_syntax_invalid_mutations` | Added. A runtime error is a failed test, while invalid target syntax has separate evidence. | Excluding a behavioral failure as a compiler-invalid mutation. |
| `test_missing_invalid_and_empty_suites_are_runner_failures` | Added. Missing ownership, malformed configuration and zero executed tests cannot produce successful evidence. | Reporting success when no owned tests execute. |

# Selection regression evidence

In a disposable checkout containing one commit that adds an inline test to `crates/packetcraftr-core/src/budget.rs`, the actual selection command was run with the original and repaired selector.

```sh
/usr/bin/python3 scripts/run_mutation.py select --base 'HEAD^' --plan selected.json
```

The original command exited zero and selected only the edited file.

```json
[{"group": "packetcraftr-core", "language": "rust", "files": ["crates/packetcraftr-core/src/budget.rs"], "reason": "changed production files"}]
```

The repaired command exited zero and selected the owning crate.

```json
[{"group": "packetcraftr-core", "language": "rust", "files": [], "reason": "full crate, tests or shared inputs changed"}]
```

With an empty Python test destination in the same checkout, the following command exited one and printed `Mutation audit failed. invalid Python mutation ownership`.

```sh
/usr/bin/python3 scripts/run_mutation.py select --full --plan invalid.json
```

# Source provenance regression evidence

Actual release-assets results from `6aa54f149b817ca7a539cbaa5618577a6d659d6b` were checked in a disposable clone. The original checker returned exit zero and `passed` for both the matching checkout and a checkout with changed test source under the same commit. With the repaired checker and changed source, the actual command below returned exit one.

```sh
/usr/bin/python3 scripts/run_mutation.py check --plan /tmp/pcr-stale-source-_1_v8cpj/plan.json --language python --output /tmp/pcr-goal-framework-rerun/scripts_release_assets_py
```

```text
Mutation audit failed. mutation artifacts do not match the tested revision, source snapshot or pinned tool version
```

The mapped CLI regression separately verifies that a matching source fingerprint passes and uncommitted source changes fail. Another regression commits an individually reviewed exclusion, then verifies that scoring succeeds against the unchanged source and publishes the applied evidence.

# Interpreter path regression evidence

A disposable project with a two-mutant Python module was measured using the real pinned Cosmic Ray installation through an interpreter path containing spaces. This is a functionality demonstration, not a mutation score for a project production module. With the unquoted test command, the following command returned exit one.

```sh
'/tmp/pcr-real-cosmic-space-63u7jpyp/real tools with spaces/bin/python' scripts/run_mutation.py run --plan /tmp/pcr-real-cosmic-space-63u7jpyp/plan.json --language python --output /tmp/pcr-real-cosmic-space-63u7jpyp/checkout/artifacts/unquoted
```

```text
Mutation audit failed. scripts/alpha.py failed. Cosmic Ray test execution evidence is missing
```

With quoting and baseline evidence validation enabled, these actual commands both returned exit zero.

```sh
'/tmp/pcr-real-cosmic-space-63u7jpyp/real tools with spaces/bin/python' scripts/run_mutation.py run --plan /tmp/pcr-real-cosmic-space-63u7jpyp/plan.json --language python --output /tmp/pcr-real-cosmic-space-63u7jpyp/checkout/artifacts/quoted
'/tmp/pcr-real-cosmic-space-63u7jpyp/real tools with spaces/bin/python' scripts/run_mutation.py check --plan /tmp/pcr-real-cosmic-space-63u7jpyp/plan.json --language python --output /tmp/pcr-real-cosmic-space-63u7jpyp/checkout/artifacts/quoted
```

The checker reported `killed` of 2, `eligible` of 2, zero invalid or equivalent exclusions, no survivors or timeouts, tool version `8.7.0` and status `passed`. The saved baseline session independently recorded successful unittest execution.

# Reviewed enforcement regression evidence

Parallel review reproduced three defects against commit `a2970e8f`. Each mapped regression failed before its repair and passed afterward. The CLI commands below were also run against the old source and the repaired worktree in controlled temporary checkouts. These functionality receipts are separate from test results and mutation scores.

For ownership containing both a passing test file and a missing second owner, this actual harness command previously returned exit zero and successful one-test evidence.

```sh
/usr/bin/python3 scripts/mutation_test_runner.py --module scripts/alpha.py
```

```text
MUTATION_RESULT {"kind": "tests", "run": 1, "failures": 0, "errors": 0}
```

The repaired command returned exit one.

```text
MUTATION_RESULT {"kind": "runner_error", "message": "selected Python test owner is not a repository test file"}
```

With an existing but empty second owner, the same command previously returned exit zero. It now returns exit one with this evidence.

```text
MUTATION_RESULT {"kind": "runner_error", "message": "selected Python test owner contains no tests"}
```

In a separate Git fixture, removing `scripts/alpha.py` and updating its ownership used this command.

```sh
/usr/bin/python3 scripts/run_mutation.py select --base c1876f302fe25d9062e2d4fe785a5b730cc6916c --plan artifacts/selected.json
```

The old selector returned exit one.

```text
Mutation audit failed. Python files have no mutation ownership: ('scripts/alpha.py',)
```

The repaired selector returned exit zero and published this complete selection.

```json
[{"group":"other","language":"rust","files":[],"reason":"full crate, tests or shared inputs changed"},{"group":"sample","language":"rust","files":[],"reason":"full crate, tests or shared inputs changed"},{"group":"scripts/beta.py","language":"python","files":["scripts/beta.py"],"reason":"full audit or shared inputs"},{"group":"scripts/mutation_results.py","language":"python","files":["scripts/mutation_results.py"],"reason":"full audit or shared inputs"},{"group":"scripts/mutation_scope.py","language":"python","files":["scripts/mutation_scope.py"],"reason":"full audit or shared inputs"},{"group":"scripts/run_mutation.py","language":"python","files":["scripts/run_mutation.py"],"reason":"full audit or shared inputs"}]
```

The analogous rename command also changed from exit one to exit zero, selecting the renamed module and every surviving owner affected by the shared configuration change.

The Rust receipt used synthetic SDK reports containing an earlier failed or timed-out build followed by a claimed test kill. The old runner and checker both returned exit zero and reported three eligible kills. With the repaired parser, these actual commands both returned exit one.

```sh
/tmp/pcr-goal-review-regressions-fixtures-luhvfr9v/failed-build-tools/python scripts/run_mutation.py run --plan artifacts/plan.json --language rust --output artifacts/after
/tmp/pcr-goal-review-regressions-fixtures-luhvfr9v/failed-build-tools/python scripts/run_mutation.py check --plan artifacts/plan.json --language rust --output artifacts/after
```

```text
Mutation audit failed. sample failed. cargo-mutants continued after an unsuccessful phase
Mutation audit failed. expected an object with string keys
```

The timed-out build produced the same refusals. The parser now requires ordered supported phases, successful preceding phases, and an outcome consistent with the final phase. The Python harness requires every declared owner to exist and contain cases. Deleted Python production files conservatively select the surviving Python scope, including after ownership updates and renames. Existing unowned files still fail selection.

# Workspace baseline and target-scope regression evidence

A separate two-crate fixture used real cargo-mutants 27.1.0. The selected crate's test passed, while its dependent crate already had a failing test before any mutation. The old runner accepted two kills and a 100 percent score for that unhealthy workspace. These are fixture measurements, with no claim about production coverage.

```sh
/usr/bin/python3 scripts/run_mutation.py run --plan artifacts/plan.json --language rust --output artifacts/run
/usr/bin/python3 scripts/run_mutation.py check --plan artifacts/plan.json --language rust --output artifacts/run
```

Before the repair, both commands exited zero and the checker reported `killed` of 2, `eligible` of 2 and status `passed`. After the repair, the run exited one before creating any mutant execution output.

```text
Mutation audit failed. sample failed. Rust workspace baseline failed
```

The subsequent check also exited one because there was no completed report. The raw SDK logs show package-only baseline commands and workspace-wide mutant commands, consistent with [the pinned baseline implementation](https://github.com/sourcefrog/cargo-mutants/blob/v27.1.0/src/lab.rs). The added explicit workspace baseline closes that gap.

In a healthy fixture, a completed narrow-file run was checked with the same command after changing only the Git-ignored plan. The old checker accepted the original file, the entire crate, and a different file under the same group and reason. The repaired checker accepted the original target, refused both changed scopes, and accepted the original again after restoring the plan.

```sh
/usr/bin/python3 scripts/run_mutation.py check --plan artifacts/plan.json --language rust --output artifacts/run
```

Both changed plans now return exit one with the following output.

```text
Mutation audit failed. mutation artifacts do not match the requested target scope
```

All three plan checks used the same source fingerprint. Target binding is independent of source binding because a selected file list can change without changing source.

# Dependency policy validation

The dependency check found the existing Tokio 1.54.0 advisory and a duplicate Windows binding required by pcap 2.5.0. Tokio is updated to the patched 1.54.1 release. The user approved one exact duplicate-version exception for `windows-sys =0.36.1`; all other duplicate, advisory, license and source rules remain unchanged. The pinned cargo-deny 0.20.2 archive was checksum-verified before this command completed successfully.

```sh
/tmp/pcr-cargo-deny/cargo-deny-0.20.2-x86_64-unknown-linux-musl/cargo-deny --locked check
```

```text
advisories ok, bans ok, licenses ok, sources ok
```
