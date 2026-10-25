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

The runner takes one snapshot of tracked and untracked, nonignored source before a run, then gives each target a disposable copy. It records the commit and a digest of that source snapshot. Cargo-mutants runs workspace tests against every selected mutant, so dependent crates can detect errors. When a package has a `build.rs`, the disposable manifest exposes it as an additional binary target so cargo-mutants can discover it. The amended manifest is retained with the results. Rust shards are numbered from one at this script's interface and translated to cargo-mutants' zero-based numbering. No mutant is sampled or silently removed.

The existing weekly CI schedule calls the full mutation workflow. PRs call the same workflow with scoped selection. Manual dispatch runs a full audit. Pushes to the default branch retain normal CI without repeating the full mutation audit. Rust runs on the existing Linux, ARM and Intel macOS, and Windows images with each supported feature profile. Eight shards per profile use one mutation worker per job, with at most four Rust jobs at once. These limits do not alter existing CI concurrency. The gate requires every platform, profile and shard, then combines their outcomes per crate. A mutant is killed when any required run catches it. Code disabled in one profile can be tested by another. A timeout never creates a kill, and a mutant is compilation-invalid only if every run that discovered it fails compilation. Python modules are checked separately. A score aggregated across modules or crates cannot make a weak group pass.

A group's score is killed mutants divided by eligible viable mutants and must be strictly greater than 90 percent. Timeouts remain in the denominator and never count as kills. Only compilation-invalid mutants and individually reviewed equivalent mutants are excluded. The checker requires a successful baseline, complete inventory, consistent shard metadata, actual test execution evidence, and results for every selected mutant. Missing reports, duplicate results, runner failures and unfinished runs fail the gate. Zero eligible mutants are reported as not applicable with the selection reason, including the invalid and equivalent counts.

Equivalent exclusions belong in `.config/mutation-exclusions.json`, one exact mutant per entry with `group`, `revision`, `identity`, and a nonempty `evidence` explanation. They apply only to that exact source revision and surviving mutant. Do not add broad patterns or exclusions merely to meet the score. Review every survivor even when the score passes.

Artifacts retain the selection plan, source revisions and digests, tool versions, raw tool reports, session databases, individual outcomes, diffs, logs, exclusions and per-group scores. The gate rejects reports from another commit, source snapshot or tool version and never treats absent artifacts as success. Python mutant identities include their source span and operator rather than a session-specific job identifier. For tool report semantics, see [cargo-mutants workspace testing](https://mutants.rs/workspaces.html), [its warning about test-only diffs](https://mutants.rs/in-diff.html), and [Cosmic Ray sessions](https://cosmic-ray.readthedocs.io/en/latest/tutorials/intro/index.html).

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
| Python JSON support | Replaced interpreter allocation measurements with all values preserved and nonfinite values rejected in a wide document. |
| Mutation enforcement | Added behavioral checks for strict score boundaries, weak groups, incomplete and duplicate results, timeouts, worker failures, shard coverage, deleted tests, shared inputs, source identity and disposable source snapshots. A real two-crate fixture verified that dependent-crate tests kill all five mutants. |
| Native workers and cleanup | Reviewed runtime, operation, sink, native worker and capture lifecycle cases. They now verify admission refusal during callbacks, TLS destruction, panic cleanup and capture shutdown, then successful replacement work after release. Published resource diagnostics remain covered. Native registry cases still need review. |
| CLI serialization | Application, stream and followup cases now verify complete flushed records, byte-budget refusal, terminal errors and worker admission after cancellation. Followup scans use injected providers that cannot access the host network. Machine rendering and remaining serialization cases still need review. |
| Scan scheduling | Replaced work counters with due-only expiry, retirement behavior, unique host/endpoint completion and bounded progress. The conservative scheduler comparison and remaining private-state checks still need review. |
| Python forwarding | Added controlled rule-budget boundaries, complete signed timestamps, exact declared-check matching and invalid-command rejection after inspecting initial survivors. Full per-module scores are still pending. |
| Protocol suites and remaining tests | Review every case, consolidate misplaced review suites, add independent expected fields where only round trips or shared implementations are compared, and cite independent vectors. Full mutation scores and the native CI matrix are still outstanding. |
| Build scripts | Added disposable binary targets for package-root `build.rs` files. A two-crate integration fixture killed all nine mutants, including deletion of the build script's configuration output. The real build scripts still require full-run survivor review. |

The audit is not complete until every existing test has a disposition, the remaining violations are repaired, and the final revision passes every required full mutation group and CI profile. Passing ordinary tests does not establish that result.

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
