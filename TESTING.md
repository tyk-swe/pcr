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

Python mutation runs execute the suites declared for their module. Ordinary CI still discovers the entire unittest suite. Ownership for the mutation tools is split between score parsing in `test_mutation_results.py`, selection in `test_mutation_scope.py`, orchestration in `test_run_mutation.py` and SDK execution in `test_run_mutation_tools.py`. The orchestration cases also exercise the parser and selector. `test_mutation_test_runner.py` owns the test harness. These files replace the former combined `test_mutation.py` without dropping cases. The four other production modules retain their existing mapped suites.

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

The existing weekly CI schedule calls the full mutation workflow. PRs call the same workflow with scoped selection. Manual dispatch runs a full audit. Pushes to the default branch retain normal CI without repeating the full mutation audit. Rust runs on the existing Linux, ARM and Intel macOS, and Windows images with each supported feature profile. Eight shards per profile use one mutation worker per job, with at most four Rust jobs at once. These limits do not alter existing CI concurrency. The gate requires every platform, profile and shard, then combines their outcomes per crate. A mutant is killed when any required run catches it. Code disabled in one profile can be tested by another. A timeout never creates a kill, and a mutant is compilation-invalid only if every run that discovered it fails compilation. Python modules are checked separately. A score aggregated across modules or crates cannot make a weak group pass.

A group's score is killed mutants divided by eligible viable mutants and must be strictly greater than 90 percent. Timeouts remain in the denominator and never count as kills. Only compilation-invalid mutants and individually reviewed equivalent mutants are excluded. The checker requires a successful baseline, complete inventory, consistent shard metadata, actual test execution evidence, and results for every selected mutant. Missing reports, duplicate results, runner failures and unfinished runs fail the gate. Zero eligible mutants are reported as not applicable with the selection reason, including the invalid and equivalent counts.

Equivalent exclusions belong in `.config/mutation-exclusions.json`, one exact mutant per entry with `group`, `revision`, `identity`, and a nonempty `evidence` explanation. Set `revision` to the score artifact's `source_revision`, the source fingerprint rather than the Git commit. This lets the review be committed without referring to its own hash. Each entry applies only to that exact source and surviving mutant. Scores publish every applied entry and its evidence. The gate still requires the current Git commit and matching worktree source. Do not add broad patterns or exclusions merely to meet the score. Review every survivor even when the score passes.

Artifacts retain the selection plan, source revisions and digests, tool versions, raw tool reports, session databases, individual outcomes, diffs, logs, exclusions and per-group scores. The gate recomputes the current worktree fingerprint, rejects reports from another commit, source snapshot or tool version, and never treats absent artifacts as success. CI stores downloaded reports and score output under ignored `mutation-results/` paths so they cannot become measured source. Python mutant identities include their source span and operator rather than a session-specific job identifier. For tool report semantics, see [cargo-mutants workspace testing](https://mutants.rs/workspaces.html), [its warning about test-only diffs](https://mutants.rs/in-diff.html), and [Cosmic Ray sessions](https://cosmic-ray.readthedocs.io/en/latest/tutorials/intro/index.html).

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
| Native workers and cleanup | Reviewed runtime, operation, sink, native worker, capture and all nine native registry cases. They now verify admission refusal during callbacks, TLS destruction, panic cleanup and capture shutdown, then successful replacement work after release. Registry tests check delivered replies and recovered capacity rather than private state. Published resource diagnostics remain covered. |
| CLI serialization | Application, stream and followup cases now verify complete flushed records, byte-budget refusal, terminal errors and worker admission after cancellation. Followup scans use injected providers that cannot access the host network. Machine rendering and remaining serialization cases still need review. |
| Scan scheduling | Replaced work counters with due-only expiry, retirement behavior, unique host/endpoint completion and bounded progress. The conservative scheduler comparison and remaining private-state checks still need review. |
| Python forwarding | Added controlled rule-budget boundaries, complete signed timestamps, exact declared-check matching and invalid-command rejection after inspecting initial survivors. Full per-module scores are still pending. |
| Protocol message suites | Reviewed all 39 message cases. Moved review and improvement cases into reference, framing, reflection and validation suites under the existing owner. Independent decoded fields supplement wire preservation, positive validation cases check complete bytes, and wire expectations cite dated sources. Other protocol tests, full mutation scores and the native CI matrix are still outstanding. |
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

# Mutation progress

The first completed exploratory forwarding run measured the source snapshot at commit `6c8698caf40c0f9c2503b867bed3b4b6f002cb51` with tree digest `6c70734e2ff5a05b24e9dc94666b84c6809a7d27bea257e04126f5589bd1129f`. It killed 1,172 of 1,765 eligible mutants, a score of 66.4 percent. Twenty compilation-invalid mutants were excluded. There were 592 survivors and one timeout, with no equivalent exclusions. This older snapshot does not establish the score of the current branch.

Survivors exposed missing cases for nonempty unmatched and unkeyed capture counts, omitted matches and evidence availability. Added cases now check retained and omitted observations on both sides, conservative reorder bounds, and valid or contradictory outcomes across evidence states. Targeted Cosmic Ray reruns killed four previously surviving arithmetic mutants in rule budgeting, omission accounting and capture totals. A complete rerun is still required before claiming any new module score.

The exploratory build-manifest run attempted all 176 mutations but produced a worker exception when Cosmic Ray tried to replace a qualified exception name inside a tuple. No score was accepted for that run. Importing the exception by name makes the mutation executable in both affected tools. Targeted reruns completed normally and killed both handler mutations. CLI regression cases also verify that failed binary, compiler and version-control commands return a failure diagnostic without publishing a success report or plan. No mutation was excluded to address the runner error.

At commit `6aa54f149b817ca7a539cbaa5618577a6d659d6b`, the release-assets rerun killed all 126 mutants, with no exclusions, survivors or timeouts. The same snapshot measured 426 of 484 eligible kills for results and 138 of 162 for selection. Those two groups remain below the threshold. Subsequent source-provenance repairs require fresh results before any current-tip score can be claimed.

The exploratory Python run completed every generated work item. It also measured 313 kills out of 458 eligible mutants for the result checker, 77 out of 156 for selection, 114 out of 126 for release assets, and 171 out of 258 for shared script support. The release-assets score exceeds the threshold, but its twelve survivors still exposed missing schema, canonical-path and byte-budget cases. Those cases have been added. Checker cases now cover all outcome classes, malformed artifacts, baseline execution, scoped exclusions and both failure counters. Complete module reruns are required to measure these repairs.

# Enforcement case audit

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
| `test_committed_additions_and_test_deletions_schedule_their_owners` | Strengthened. A real local commit adds source and deletes tests, then selects their production owners. Git configuration is isolated from the host. | Treating a file absent from the base revision as a fatal diff error. |
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
