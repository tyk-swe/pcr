# BASE-02: Prove and document the complete offline batch

Status: ready-for-agent
Blocked by: HTTP-T02, HTTP-B02, SPLIT-02, GATE-02
Size: small–medium integration and release work
Spec: [batch contract](../spec.md)

## What to build

1. Verify every numbered acceptance case in the four feature specs has a
   behavior regression in its owning test target. Fill a coverage table in
   this ticket's Comments using case ID, test name, command, and result.
2. Update `README.md`, `docs/tasks.md`, `docs/analysis-resources.md`,
   `docs/resource-presets.md`, `docs/consumer-compatibility.md`,
   `docs/migration-unreleased.md`, and Unreleased for the actual final behavior.
   Include runnable HTTP listing/extraction, split, and gated expert examples.
   State header-availability timing, preserved content coding, source metadata
   in every part, closed staging handles, and gate/report-selector independence.
3. Generate all new output examples from the real CLI and validate them.
   Keep hand-authored negative/mutation fixtures as tests. Verify generated
   help, completions, and man pages include each flag and the split command.
4. Confirm the v7 archive inventory and the v6/v7 reference-consumer tests.
   Ensure architecture checks and the external consumer still pass. Compile
   existing HTTP/capture fuzz targets after API changes; extend those targets
   to exercise the new bounded core seams, rather than adding an unbounded
   second parser. Add no claim of a fuzz campaign unless it was run.
5. Record the exact final revision/feature profile and validation results.
   Keep fixtures synthetic and offline; native runtime evidence is not needed
   for this batch, which changes no native providers or live workflows.

## Required validation

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked --workspace --no-default-features
python3 scripts/check-architecture.py
python3 scripts/test-output-consumer.py
python3 scripts/test-forwarding-regression.py
python3 scripts/test-native-capture.py
python3 scripts/test-verify-archive.py
python3 scripts/check-external-consumer.py
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
RUSTFLAGS="-D warnings" cargo +nightly-2026-08-28 check --locked --manifest-path fuzz/Cargo.toml --bins
```

The all-feature Linux checks require `libpcap-dev`; use the pinned toolchains.
Also run `generated_documentation_contracts`, `resource_diagnostic_contracts`,
the new feature targets, and the current conformance suite if not already
included in the workspace runs. Avoid repeating passed commands without a
subsequent relevant change. Report an unavailable check honestly.

## Acceptance

- [ ] All feature acceptance IDs map to meaningful passing tests.
- [ ] v6 history is unchanged; real current output/examples/assets agree on v7.
- [ ] Portable execution succeeds with no provider construction or networking.
- [ ] Every new bound has correct resource diagnostics and preset precedence.
- [ ] No source-layout tests, new unsafe code, or accidental core→workflow edge.
- [ ] Documentation describes the final implementation and exact limitations.
- [ ] Applicable CODEOWNERS review is requested with the implementation PR.

## Comments

### BASE-02 execution — branch `tyk/oi-base-02` (worktree `wt/base-02`)

**Revision / feature profile.** Base revision `d7e32f49` ("docs: mark HTTP-B02
resolved") — the branch already contains all four feature merges
(HTTP-T02 `6023f7d6`, HTTP-B02 `f2429e98`, SPLIT-02 `80305557`,
GATE-02 `4e6bd520`) plus the v7 output family (`a2796199`). Validation ran on
the pinned toolchain (`rust-toolchain.toml`) with
`CARGO_TARGET_DIR=/home/ubuntu/code/pcr/1/target-shared`; profiles: all-features
Linux (with libpcap) and portable `--no-default-features`. This batch changes
no native providers or live workflows, so no native runtime evidence is
required.

**Coverage table — all 65 acceptance cases verified.** Every case maps to a
passing behavior regression in its owning target; results are from
`cargo test --locked --workspace --all-features` (2008 passed / 0 failed /
16 ignored; the ignores are the isolated-native suite and the example
regenerator). Tests added by this ticket are marked ★.

#### HTTP header transactions (HT01–HT15)

| Case | Test | Owning target | Result |
| --- | --- | --- | --- |
| HT01 | `paired_transaction_marks_header_availability_and_emits_before_the_message`; `transactions_publish_a_paired_row_in_every_format` | `packetcraftr-core` `http_analysis_contracts`; `packetcraftr-cli` `http_contracts` | pass |
| HT02 | `informational_responses_accumulate_until_the_final_response_pairs`; `transactions_track_informational_responses_until_the_final_response` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT03 | `orphan_responses_emit_independently_without_guessed_grouping`; `transactions_mark_unsolicited_responses_orphans` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT04 | `pipelined_requests_pair_fifo_matching_message_requests`; `transactions_pair_pipelined_requests_fifo_with_canonical_zero_intervals` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT05 | `response_headers_pair_while_the_request_body_is_incomplete`; `transaction_records_can_precede_the_message_records_they_cite` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT06 | `head_connect_and_upgrade_responses_pair_without_tunnel_body_claims`; `transactions_settle_paired_rows_for_head_and_upgrades` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT07 | `gap_filled_and_out_of_order_heads_mark_the_releasing_frame`; `ip_fragmented_response_marks_the_completing_fragment_frame`; `transaction_markers_track_reassembly_not_delivery` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT08 | `clock_regression_keeps_signed_wait_and_span_intervals`; `transaction_intervals_publish_signed_nanoseconds`; `production_typed_event_variants_are_schema_valid` | core `http_analysis_contracts`; cli `http_contracts`; `ndjson_conformance` | pass |
| HT09 | `heads_in_one_delivery_share_markers_and_canonical_zero_intervals`; `transactions_pair_pipelined_requests_fifo_with_canonical_zero_intervals` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT10 | `reused_generations_and_eof_retire_pending_requests_once_in_index_order`; `transactions_retire_generations_and_eof_pending_requests_in_request_index_order` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT11 | `rejected_heads_create_no_rows_but_bad_framing_still_associates`; `transactions_associate_malformed_and_misframed_heads_by_parsed_boundary` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT12 | `disabled_collectors_emit_no_transactions_and_empty_runs_count_zero`; `transactions_stay_empty_disabled_and_report_zero_counts_when_empty`; `transactions_respect_stream_selection_and_epoch_bounds` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT13 | `transaction_charges_share_the_classified_retained_budget`; `application_output_budget_charges_transaction_records_exactly`; `retained_byte_allowance_failure_reports_a_classified_policy_error`; `ndjson_budget_preserves_the_emitted_prefix_on_exhaustion` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT14 | `sink_failure_surfaces_as_output_and_stops_all_later_writes` (queued events unpublished); `broken_stdout_reports_an_incomplete_ndjson_stream` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HT15 | `transaction_configuration_seals_on_the_first_observe_attempt` | core `http_analysis_contracts` | pass |

#### HTTP body export (HB01–HB17)

| Case | Test | Owning target | Result |
| --- | --- | --- | --- |
| HB01 | `consume_with_delivers_binary_body_bytes_exactly_in_any_segmentation`; `only_the_selected_message_body_reaches_the_sink`; `body_export_publishes_the_exact_selected_bytes_in_every_format` | core `http_framing_contracts` + `http_analysis_contracts`; cli `http_contracts` | pass |
| HB02 | `consume_with_emits_only_chunk_data_once_in_any_segmentation`; `chunked_body_emits_only_data_in_every_two_segment_split`; `body_export_writes_only_concatenated_chunk_data` | core `http_framing_contracts` + `http_analysis_contracts`; cli `http_contracts` | pass |
| HB03 | `body_export_preserves_coded_bytes_without_decoding` (exact coded bytes + sha256 asserted) | cli `http_contracts` | pass |
| HB04 | `consume_with_close_delimited_streams_until_a_clean_fin`; `close_delimited_body_streams_until_a_clean_fin`; `body_export_of_a_close_delimited_body_requires_a_clean_close` | core `http_framing_contracts` + `http_analysis_contracts`; cli `http_contracts` | pass |
| HB05 | `bodyless_and_empty_selected_messages_invoke_no_writes`; `body_export_empty_bodies_publish_and_upgrades_do_not` | core `http_analysis_contracts`; cli `http_contracts` | pass |
| HB06 | `body_export_reassembles_each_body_byte_exactly_once`; `only_the_selected_message_body_reaches_the_sink` | cli `http_contracts`; core `http_analysis_contracts` | pass |
| HB07 | `body_selection_arguments_fail_as_usage_without_staging`; `body_selection_numbers_messages_within_this_invocation` | cli `http_contracts` | pass |
| HB08 | `body_export_terminal_status_failures_publish_nothing` | cli `http_contracts` | pass |
| HB09 | `body_export_never_publishes_after_a_late_capture_failure` | cli `http_contracts` | pass |
| HB10 | `body_export_publishes_despite_later_ordinary_issues` | cli `http_contracts` | pass |
| HB11 | `body_export_never_clobbers_an_existing_destination`; `stdout_failure_before_and_after_persistence`; `a_destination_appearing_after_staging_fails_publish_without_clobbering`; `a_sealed_file_rereads_the_absent_destination_at_publish` | cli `http_contracts`; cli lib `staged_output` tests | pass |
| HB12 | `consume_with_sink_failure_is_terminal_and_leaves_the_span_uncommitted`; `sink_failure_surfaces_as_output_and_stops_all_later_writes` | core `http_framing_contracts` + `http_analysis_contracts` | pass |
| HB13 | `consume_with_never_delivers_bytes_beyond_the_ceiling`; `over_ceiling_bodies_never_reach_the_sink`; `body_export_limit_and_metadata_budget_failures_publish_nothing` | core `http_framing_contracts` + `http_analysis_contracts`; cli `http_contracts` | pass |
| HB14 | `stdout_failure_before_and_after_persistence` (artifact remains after post-commit output failure) | cli `http_contracts` | pass |
| HB15 | `consume_with_borrows_bounded_spans_and_buffers_nothing_proportional`; `a_large_body_arrives_in_spans_bounded_by_the_deliveries`; `body_export_of_a_large_body_in_bounded_segments` | core `http_framing_contracts` + `http_analysis_contracts`; cli `http_contracts` | pass |
| HB16 | `body_export_publishes_the_exact_selected_bytes_in_every_format`; `body_export_reads_stdin_and_compressed_sources_identically`; `transactions_and_a_body_sink_compose`; `every_published_output_example_validates_against_the_schema` | cli `http_contracts`; core `http_analysis_contracts`; `published_example_matrix` | pass |
| HB17 | `body_selection_rejects_zero_repeated_and_late_targets`; `body_selection_arguments_fail_as_usage_without_staging` | core `http_analysis_contracts`; cli `http_contracts` | pass |

#### Capture split (SP01–SP17)

| Case | Test | Owning target | Result |
| --- | --- | --- | --- |
| SP01 | `part_counts_and_ranges_cover_every_boundary_case`; `an_empty_source_produces_one_metadata_only_part`; `split_writes_exactly_named_parts_that_independently_reread`; `split_writes_one_metadata_part_for_an_empty_capture` | core `capture_split_contracts`; cli `capture_split_contracts` | pass |
| SP02 | `classic_parts_match_selections_in_both_byte_orders_and_precisions` | core `capture_split_contracts` | pass |
| SP03 | `every_part_preserves_sections_metadata_and_interface_context` | core `capture_split_contracts` | pass |
| SP04 | `packet_block_kinds_and_time_regressions_are_copied_raw` | core `capture_split_contracts` | pass |
| SP05 | `concatenated_part_packet_records_reproduce_the_source_sequence`; `split_writes_exactly_named_parts_that_independently_reread` | core `capture_split_contracts`; cli `capture_split_contracts` | pass |
| SP06 | `invalid_input_fails_before_any_sink_callback`; `split_rejects_malformed_input_before_any_destination`; `split_writes_one_metadata_part_for_an_empty_capture` | core `capture_split_contracts`; cli `capture_split_contracts` | pass |
| SP07 | `limits_hold_at_equality_and_fail_one_over`; `invalid_option_and_limit_ranges_fail_before_source_consumption`; `split_enforces_declared_finite_limits` | core `capture_split_contracts`; cli `capture_split_contracts` | pass |
| SP08 | `split_encoded_ceiling_trips_below_compressor_finish_bytes`; `split_report_counts_exact_encoded_bytes_below_the_compressor`; `compressor_finish_and_trailer_bytes_are_counted_below_the_codec`; `encoded_limit_refusal_keeps_its_policy_classification_through_codec_errors`; `the_shared_refusal_latches_the_typed_policy_error`; `equality_with_the_encoded_ceiling_is_accepted` | cli `capture_split_contracts`; cli lib `commands::split` tests | pass |
| SP09 | `a_changed_same_size_source_cannot_succeed`; `a_source_extended_between_passes_cannot_succeed` | core `capture_split_contracts` | pass |
| SP10 | `split_never_overwrites_an_existing_name_and_writes_nothing_before_it`; `split_never_follows_a_dangling_symlink_at_a_predicted_name`; `split_requires_an_existing_output_directory`; `every_predicted_destination_is_checked_before_any_generation`; `a_dangling_symlink_at_a_predicted_name_is_never_overwritten`; `a_source_at_a_predicted_name_is_never_used_as_output`; `the_output_directory_must_exist_and_be_a_directory` | cli `capture_split_contracts`; cli lib `commands::split` tests | pass |
| SP11 | `a_failed_commit_rolls_back_only_what_this_invocation_published`; `a_failed_rollback_reports_the_path_that_remains`; `interruption_at_a_later_commit_rolls_back_the_published_files`; `a_seal_sync_failure_abandons_the_staged_temporary_file`; `a_deadline_during_generation_stops_before_any_commit` | cli lib `staged_output` + `commands::split` tests | pass |
| SP12 | `generation_opens_one_output_descriptor_at_a_time` | cli lib `commands::split` tests | pass |
| SP13 | `split_keeps_published_parts_when_the_report_write_fails` | cli `capture_split_contracts` | pass |
| SP14 | `split_accepts_redirected_stdin_and_compressed_input`; `split_compresses_every_part_independently_of_input_and_stdout_format`; `split_rejects_terminal_stdin`; `every_published_output_example_validates_against_the_schema` | cli `capture_split_contracts`; `published_example_matrix` | pass |
| SP15 | `split_rejects_foreign_and_out_of_range_flags_without_destinations` ★ | cli `capture_split_contracts` | pass |
| SP16 | `parts_reread_independently_under_the_same_reader_settings`; `split_writes_exactly_named_parts_that_independently_reread` | core `capture_split_contracts`; cli `capture_split_contracts` | pass |
| SP17 | `cancellation_stops_cached_metadata_replay_without_source_reads`; `split_rejects_foreign_and_out_of_range_flags_without_destinations` ★; `a_deadline_during_generation_stops_before_any_commit` | core `capture_split_contracts`; cli `capture_split_contracts`; cli lib `commands::split` tests | pass |

#### Expert gate (EG01–EG16)

| Case | Test | Owning target | Result |
| --- | --- | --- | --- |
| EG01 | `absent_fail_on_preserves_report_only_behavior_and_null_gate` | cli `expert_gate_contracts` | pass |
| EG02 | `each_threshold_counts_observed_once_and_triggering_by_severity`; `gate_counts_every_finding_once_per_threshold` | core `expert_gate_contracts`; cli `expert_gate_contracts` | pass |
| EG03 | `allowance_below_equal_and_above_the_trigger_count`; `equality_at_both_boundaries_passes`; `allowance_boundary_passes_at_equality_and_fails_above` | core `expert_gate_contracts`; cli `expert_gate_contracts` | pass |
| EG04 | `matched_frames_below_equal_and_above_the_minimum`; `minimum_frames_boundary_inconclusive_below_and_passes_at_equality` | core `expert_gate_contracts`; cli `expert_gate_contracts` | pass |
| EG05 | `an_observed_violation_wins_over_insufficient_coverage`; `allowance_violation_wins_over_insufficient_coverage` | core `expert_gate_contracts`; cli `expert_gate_contracts` | pass |
| EG06 | `empty_match_set_with_gate_is_inconclusive_with_completed_report` | cli `expert_gate_contracts` | pass |
| EG07 | `selector_hidden_findings_still_fail_the_gate` | cli `expert_gate_contracts` | pass |
| EG08 | `multi_finding_frames_and_retention_omission_keep_gate_counts_exact` | cli `expert_gate_contracts` | pass |
| EG09 | `the_gate_observes_the_collector_stream_including_trailing_findings`; `eof_trailing_finding_is_counted_before_gate_evaluation` | core `expert_gate_contracts`; cli `expert_gate_contracts` | pass |
| EG10 | `zero_minimum_frames_is_a_typed_usage_error`; `gate_flags_validate_before_input_opens` | core `expert_gate_contracts`; cli `expert_gate_contracts` | pass |
| EG11 | `execution_failures_publish_no_completed_gate`; `cancellation_before_publication_fabricates_no_completed_gate`; `broken_output_overrides_verdict_exit_status` | cli `expert_gate_contracts` | pass |
| EG12 | `verdicts_publish_consistently_across_all_formats` | cli `expert_gate_contracts` | pass |
| EG13 | `broken_output_overrides_verdict_exit_status` | cli `expert_gate_contracts` | pass |
| EG14 | `analysis_domain_inputs_feed_the_same_gate` | cli `expert_gate_contracts` | pass |
| EG15 | `filtered_tail_frame_keeps_eof_attribution_and_gate_counts_it` | cli `expert_gate_contracts` | pass |
| EG16 | `incomplete_ip_evidence_without_findings_passes` | cli `expert_gate_contracts` | pass |

Auxiliary evaluator invariants also covered: `counting_is_order_independent`,
`report_carries_the_configured_options_and_observed_counts`
(core `expert_gate_contracts`).

**Gaps found and tests added.**

- SP15/SP17 (CLI half): no process-level regression covered foreign option
  rejection, out-of-range `--max-duration-ms` bounds, invalid/missing
  `--frames-per-file`, NDJSON terminal `cli.error`, and "no destination
  created". Added
  `split_rejects_foreign_and_out_of_range_flags_without_destinations` to
  `crates/packetcraftr-cli/tests/capture_split_contracts.rs`.
- Generated documentation: added explicit assertions for every new batch flag
  (`--transactions`, `--body-message`, `--write`, `--frames-per-file`,
  `--write-dir`, `--compression`, `--max-files`,
  `--max-split-metadata-records`, `--max-split-metadata-bytes`,
  `--max-split-output-bytes`, `--max-duration-ms`, `--fail-on`,
  `--allow-findings`, `--minimum-frames`) and the `split` command in
  completions and man pages, in
  `crates/packetcraftr-cli/tests/generated_documentation_contracts.rs`.
- Fuzz: extended the existing bounded `fuzz/fuzz_targets/http_pipeline.rs`
  with a `CountingSink` (`http::BodySink`), bounded body delivery/refusal,
  `Collector::with_transactions`/`with_body_sink`, expert finding collection,
  `expert::gate::Gate` threshold selection and truth-table invariants. The
  existing `capture_transform` target already exercises the split seam; it was
  additionally rustfmt-formatted. No new target and no unbounded parser added;
  no fuzz campaign was run — compile checks only.

**Docs.** `README.md` (split paragraph + runnable `http --transactions`,
`--body-message/--write`, `split`, gated `expert` examples),
`docs/tasks.md` (runnable listing→extraction pair with identical selector
settings, runnable `--transactions`, real gated example on
`clock-regression.pcap`, staging-handle/commit/rollback and
artifact-remains-on-post-commit-failure statements),
`docs/analysis-resources.md` (one open output descriptor/compressor at a time;
sealed staging handles),
`docs/resource-presets.md`/`docs/consumer-compatibility.md`/
`docs/migration-unreleased.md` verified already accurate for the final
behavior; `CHANGELOG.md` `[Unreleased]` corrected the stale
"until the feature tickets land" v7 wording.

**Output examples.** `refresh_published_transaction_examples` regenerated the
transaction documents from the real CLI serializer (no drift). Verified
byte-identical real-serializer provenance for `output-split-*.json` (fresh CLI
run on `tls-handshake.pcapng` matched exactly apart from the directory path),
`output-http-body-export-success.json` (fresh run produced the identical
`body_export` record and sha256) and `output-expert-gate-*.json` (fresh
`clock-regression.pcap` gate run matches the published shape/verdict fields).
Every `output-*` example validates against
`schemas/packetcraftr.output.v7.schema.json` via
`published_example_matrix`; the archived v6 schema and v6 frozen fixture are
untouched.

**Archive / consumers.** `scripts/verify-archive.py` `ASSETS` lists both
schemas (`packetcraftr.output.v6.schema.json`,
`packetcraftr.output.v7.schema.json`) and both frozen fixtures
(`examples/consumers/fixtures/v6-forwarding.json`,
`v7-forwarding.json`); `.github/workflows/release.yml` ships the full
`schemas/` tree and both fixtures. Reference consumers: 27/27
`test-output-consumer.py` tests pass over both v6 and v7 fixtures.

**Exact validation results** (all run on `tyk/oi-base-02`, shared target dir):

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | pass (0 warnings) |
| `cargo test --locked --workspace --all-features` | pass — 2008 passed, 0 failed, 16 ignored across 151 test binaries (ignores: 6× isolated native launcher, 1× isolated netlink namespace test, 1× example regenerator, 8× measurement/perf fixtures run explicitly) |
| `cargo test --locked --workspace --no-default-features` | pass — 1933 passed, 0 failed across 151 test binaries |
| `python3 scripts/check-architecture.py` | pass — "Four-crate dependency direction verified" |
| `python3 scripts/test-output-consumer.py` | pass — 27 tests OK (v6 + v7 fixtures) |
| `python3 scripts/test-forwarding-regression.py` | pass — 8 tests OK |
| `python3 scripts/test-native-capture.py` | pass — 5 tests OK (offline harness; no native hardware exercised) |
| `python3 scripts/test-verify-archive.py` | pass — 8 tests OK, 1 skipped (native-archive smoke needs `PACKETCRAFTR_ARCHIVE_BINARY`; unavailable in this environment) |
| `python3 scripts/check-external-consumer.py` | pass — external BOM consumer compiled and `public_provider_composition` passed |
| `cargo fmt --manifest-path fuzz/Cargo.toml -- --check` | pass |
| `RUSTFLAGS="-D warnings" cargo +nightly-2026-08-28 check --locked --manifest-path fuzz/Cargo.toml --bins` | pass — pinned nightly available; `dev` profile finished clean |

Focused reruns after the changes: `capture_split_contracts` (cli) 16/16,
`generated_documentation_contracts` 2/2 — all included in the workspace runs
above, which also covered `http_contracts`, `expert_gate_contracts`,
`aggregate_schema_conformance`, `ndjson_conformance`,
`published_example_matrix`, `resource_diagnostic_contracts`, and the core
feature targets.

**Unavailable / not claimed:** the real-release-archive smoke
(`verify-archive.py --root …` and the `PACKETCRAFTR_ARCHIVE_BINARY` test leg)
— no release archive exists in this environment; the checker logic itself is
covered by `test-verify-archive.py`. No fuzz campaign was run. No native
runtime evidence was required (offline batch; no provider/workflow changes).

**Sanity checks.** `unsafe` scan of `packetcraftr-core`, `packetcraftr-cli`,
`packetcraftr` and non-`platform` `packetcraftr-netio` sources shows only
`#![forbid(unsafe_code)]` markers — no unsafe added. Architecture check
confirms no core→workflow edge. No source-layout tests added.
