# PacketcraftR: 50 improvements

This branch implements exactly the 50 numbered behavior/documentation improvements
below. Tests, fixtures, review corrections and this acceptance map support those
items and do not add to the count. Version and dependencies are unchanged.
No publishing, pushing or merging is part of this batch.

Rows 3–20 abbreviate implementation paths relative to
`crates/packetcraftr-core/src/`. Rows 21–36 abbreviate crate names relative to
`crates/`. Acceptance test names locate cases through `rg` in the linked module
or its associated test module.

| # | Improvement and implementation | Acceptance case |
|---|---|---|
| 1 | [crates/packetcraftr-core/src/expression/syntax.rs](crates/packetcraftr-core/src/expression/syntax.rs): delimiter stack rejects mismatched close at crossing | `crossed_delimiters_fail_at_the_crossing_and_quotes_are_preserved`: crossed nesting errors at byte 2, ordered nesting and quoted/escaped delimiters pass |
| 2 | [crates/packetcraftr-core/src/transform/fields.rs](crates/packetcraftr-core/src/transform/fields.rs): check input count before compiling edits | `assignment_limit_precedes_compilation`: 65 invalid assignments return limit first; 64 reach field validation |
| 3 | [protocol/application/sip.rs](crates/packetcraftr-core/src/protocol/application/sip.rs): nonempty request target | `improvement_text_targets_and_content_lengths`: empty SIP target rejected, `*` accepted |
| 4 | [protocol/application/rtsp.rs](crates/packetcraftr-core/src/protocol/application/rtsp.rs): nonempty request target | Same test: empty RTSP target rejected, `*` accepted |
| 5 | [protocol/application/text_message.rs](crates/packetcraftr-core/src/protocol/application/text_message.rs): nonempty ASCII digits before usize parse | Same test: signed/empty Content-Length rejected for SIP and RTSP |
| 6 | [protocol/application/text_message.rs](crates/packetcraftr-core/src/protocol/application/text_message.rs): legal unfolding then trim only SP/HTAB | Same test: folded/SP/HTAB accepted; VT/FF/NBSP and interior whitespace rejected |
| 7 | [protocol/framing.rs](crates/packetcraftr-core/src/protocol/framing.rs): checked usize bulk-length conversion | `improvement_resp_framing_matches_canonical_decoder_and_depth`: i64::MAX bulk fails safely under buffer ceiling; zero and three-byte bulk frames exact |
| 8 | [protocol/framing.rs](crates/packetcraftr-core/src/protocol/framing.rs): canonical decimal check for lengths and integer nodes | Same test: +1, 01, -0, leading-space integers and lengths refused, matching decoder recognition |
| 9 | [protocol/framing.rs](crates/packetcraftr-core/src/protocol/framing.rs): depth checked on every node | Same test: 15 parent arrays accept scalar/empty/null/bulk leaves; 16 refuse all leaf kinds, matching decoder |
| 10 | [protocol/application/resp.rs](crates/packetcraftr-core/src/protocol/application/resp.rs): null data must be empty Bytes/List of matching kind | `improvement_resp_null_reflection_requires_canonical_empty_data`: canonical empties accepted, nonempty or wrong types refused |
| 11 | [protocol/application/sip.rs](crates/packetcraftr-core/src/protocol/application/sip.rs): body layout following header terminator | `improvement_application_layouts_expose_exact_content_ranges`: exact `abc` and empty body slices |
| 12 | [protocol/application/rtsp.rs](crates/packetcraftr-core/src/protocol/application/rtsp.rs): textual body range, retain existing binary branch | Same test: textual `abc`, empty, and interleaved payload exact; existing interleaved layout regression retained |
| 13 | [protocol/application/memcached.rs](crates/packetcraftr-core/src/protocol/application/memcached.rs): checked total and bounded extras/key/value offsets | Same test: extras E, key KE, value val exact |
| 14 | [security/indicators.rs](crates/packetcraftr-core/src/security/indicators.rs) adds `Document::validate`; [security/capture.rs](crates/packetcraftr-core/src/security/capture.rs) calls it for hunt construction | `directly_constructed_hunt_documents_are_validated_and_normalized`: invalid ID/domain/schema refused, uppercase trailing-dot domain normalized; existing indicator tests cover parsed docs |
| 15 | [security/capture/dns_anomalies.rs](crates/packetcraftr-core/src/security/capture/dns_anomalies.rs): examine every label except final, group by following suffix | `dns_checks_inner_labels_and_groups_by_following_domain_with_existing_budget`: inner label grouped and lowercased, terminal/single label excluded, second group hits configured limit |
| 16 | [security/capture.rs](crates/packetcraftr-core/src/security/capture.rs) stores Duration; [security/capture/beacons.rs](crates/packetcraftr-core/src/security/capture/beacons.rs) subtracts integer time then converts interval | `nanosecond_beacon_intervals_retain_precision_at_modern_epochs`: 1 ns intervals at modern epoch yield mean 1e-9 and CV zero |
| 17 | [protocol/application/mqtt.rs](crates/packetcraftr-core/src/protocol/application/mqtt.rs): single-pass subscription level validation | `improvement_mqtt_subscription_and_will_topics`: both SUBSCRIBE/UNSUBSCRIBE accept full-level + and final #, reject embedded/repeated/nonfinal wildcards and empty topic |
| 18 | [protocol/application/mqtt.rs](crates/packetcraftr-core/src/protocol/application/mqtt.rs): shared `topic_name` for PUBLISH and CONNECT Will Topic | Same test: valid will name accepted; empty/+/# names refused |
| 19 | [protocol/application/ldap.rs](crates/packetcraftr-core/src/protocol/application/ldap.rs): Reader-based BER ranges for ID content, operation tag, fields content and complete controls | `improvement_application_layouts_expose_exact_content_ranges`: exact ordinary BER and long-form envelope/operation ranges |
| 20 | [protocol/application/coap.rs](crates/packetcraftr-core/src/protocol/application/coap.rs): parse token/options boundaries, payload starts after marker | Same test: exact token, repeated options, payload sans marker, and empty token/options/payload |

| # | Improvement and implementation | Acceptance case |
|---|---|---|
| 21 | [packetcraftr/src/target/model.rs](crates/packetcraftr/src/target/model.rs): normalize original hostname spelling after validating labels without terminal dot. | `network_improvements_absolute_hostname_and_resolver_spelling`: lowercase dotted display/JSON, distinct equality, resolver receives final dot. |
| 22 | [packetcraftr/src/clock.rs](crates/packetcraftr/src/clock.rs): pacing checks live deadline, preserving Infallible. | `network_improvements_clock_stops_at_spent_deadline`: ten-second sleep returns promptly under zero deadline. |
| 23 | [packetcraftr-netio/src/udp.rs](crates/packetcraftr-netio/src/udp.rs): receive one byte beyond ceiling; clamp retained bytes. | `retained_udp_response_limit_is_exact`: loopback UDP payloads 0, 3, 4, 5, 64 against ceiling 4. |
| 24 | [packetcraftr-netio/src/capture/filter.rs](crates/packetcraftr-netio/src/capture/filter.rs): allow tcp-ece/tcp-cwr constants. | `ecn_flags_are_numeric_symbols`: combined ECN expression accepted; hostname rejected. |
| 25 | [packetcraftr-netio/src/tls/verification.rs](crates/packetcraftr-netio/src/tls/verification.rs): preflight every PEM marker, reject non-certificate labels before certificate-only decoder. | `ca_bundles_reject_every_other_pem_section`: valid generated test CA accepted; key/public/unknown alone and mixed rejected. |
| 26 | [packetcraftr-netio/src/interface.rs](crates/packetcraftr-netio/src/interface.rs), [packetcraftr/src/route/interface.rs](crates/packetcraftr/src/route/interface.rs): check interruption after native/provider enumeration, including errors. | `network_improvements_interface_ambiguity_and_late_enumeration`: injected callback cancels before returning matching identity; interruption wins. |
| 27 | [packetcraftr/src/route/interface.rs](crates/packetcraftr/src/route/interface.rs): reject distinct identities matching a name/index; duplicate identical IDs remain one identity. | `network_improvements_interface_ambiguity_and_late_enumeration`: duplicate names/different indexes and duplicate indexes/different names rejected. |
| 28 | [packetcraftr/src/route/planner.rs](crates/packetcraftr/src/route/planner.rs), [route/error.rs](crates/packetcraftr/src/route/error.rs): reject empty name/zero index route identity with classified error. | `network_improvements_route_deadline_cache_and_identity`: injected route with zero index rejected before planning. |
| 29 | [packetcraftr-netio/src/route/normalize.rs](crates/packetcraftr-netio/src/route/normalize.rs): rank scope before prefix. | `scope_precedes_prefix_specificity`: public source beats private source matching default prefix. |
| 30 | [packetcraftr/src/target/resolver.rs](crates/packetcraftr/src/target/resolver.rs), [netio resolution.rs](crates/packetcraftr-netio/src/resolution.rs): set-backed address deduplication retaining vector order and limit. | `network_improvements_distinct_resolver_order_and_limit`: [b,a,b,a] produces [b,a], overflow counts unique addresses; `native_resolver_retains_unique_addresses_in_first_seen_order` covers native resolver duplicates, limits and empty input. |
| 31 | [packetcraftr/src/route/planner.rs](crates/packetcraftr/src/route/planner.rs), [route/cache.rs](crates/packetcraftr/src/route/cache.rs), netio [route.rs](crates/packetcraftr-netio/src/route.rs): enforce before/after callbacks and cached results. | `network_improvements_route_deadline_cache_and_identity`: expired cache hit never calls provider, late cancellation rejects result, expired planning never calls provider. |
| 32 | [packetcraftr/src/policy/authorization.rs](crates/packetcraftr/src/policy/authorization.rs): wrap public resolution/authorization in entry and exit control checks. | `network_improvements_numeric_and_custom_resolution_boundaries`: numeric target under zero deadline and overridden resolver with late parent cancellation rejected. |
| 33 | [packetcraftr/src/neighbor/resolver.rs](crates/packetcraftr/src/neighbor/resolver.rs): attach full parent to response waits and check before/after reads. | `parent_cancellation_reaches_reads_and_prevents_unsent_attempts`: response callback cancels ancestor-only token; child read gate observes it. |
| 34 | [packetcraftr/src/neighbor/resolver.rs](crates/packetcraftr/src/neighbor/resolver.rs): live control gate immediately before send, increment attempts only after gate. | `parent_cancellation_reaches_reads_and_prevents_unsent_attempts`: pre-request drain cancels ancestor; zero sends and zero attempts. |
| 35 | netio [capture.rs](crates/packetcraftr-netio/src/capture.rs), [capture/group.rs](crates/packetcraftr-netio/src/capture/group.rs), packetcraftr [exchange/executor.rs](crates/packetcraftr/src/exchange/executor.rs), [neighbor/resolver.rs](crates/packetcraftr/src/neighbor/resolver.rs): validate names/indexes before single/group provider activation. | `incomplete_capture_identities_and_nul_are_rejected`: empty name/zero index rejected by single validation and group construction, prior to provider access; `invalid_group_never_calls_injected_capture_provider` and `incomplete_capture_identity_never_reaches_injected_provider` prove invalid identities never reach fake providers. |
| 36 | [packetcraftr-netio/src/capture.rs](crates/packetcraftr-netio/src/capture.rs): reject interior NUL in shared request validation. | `incomplete_capture_identities_and_nul_are_rejected`: NUL filter rejected in both single request validation and group construction. |

| # | Improvement and implementation | Acceptance case |
|---|---|---|
| 37 | [scripts/script_support.py](scripts/script_support.py), [scripts/release_assets.py](scripts/release_assets.py): reject Windows device components including extensions and spaced stems. | `test_device_components_and_ancestor_collisions_are_rejected`: CON, mixed-case NUL, COM/LPT, superscript digits and spaced device stems refused. |
| 38 | [scripts/release_assets.py](scripts/release_assets.py): casefold paths and reject either ancestor direction across inventories. | Same test: a versus A/b and a/B versus A refused across source/generated inventories. |
| 39 | [scripts/build-manifest.py](scripts/build-manifest.py): shared complete portable-basename rules for binary metadata. | `test_binary_name_is_not_an_archive_path`: invalid punctuation, trailing dots/spaces and reserved devices rejected. |
| 40 | [scripts/build-manifest.py](scripts/build-manifest.py): reject compiler identity control characters except TAB/CR/LF. | `test_compiler_identity_preserves_multiline_but_rejects_controls`: multiline CRLF and tabs accepted; NUL, ESC, DEL and C1 NEL rejected. |
| 41 | [scripts/release-assets.json](scripts/release-assets.json), [scripts/release_assets.py](scripts/release_assets.py): package fixture manifest and every capture/document; validate references on inventory load. | `test_all_protocol_fixture_references_exist_and_are_packaged`: actual references exist; missing inventory entry and missing file fail. |
| 42 | [crates/packetcraftr-cli/src/commands/registry/help.rs](crates/packetcraftr-cli/src/commands/registry/help.rs): extract inline and block Example/Examples text. | `inline_and_block_examples_survive_short_help`: inline command and multiline examples preserved. |
| 43 | Same help module: place every in selection and decoding heading. | `every_is_a_frame_selection_option`: heading agrees with frames. |
| 44 | [crates/packetcraftr-cli/src/command_options/selectors.rs](crates/packetcraftr-cli/src/command_options/selectors.rs): require nonempty ASCII decimal stream index. | `stream_indexes_are_unsigned_decimal`: signs, whitespace, Unicode digits, empty and overflow rejected; zero and leading zeros accepted. |
| 45 | [crates/packetcraftr-cli/src/command_options/decode.rs](crates/packetcraftr-cli/src/command_options/decode.rs): trim then require decimal port digits before existing range validation. | `decode_as_ports_are_unsigned_decimal_with_whitespace`: signed/empty/Unicode/zero/overflow rejected; whitespace and leading zeros accepted. |
| 46 | [crates/packetcraftr-cli/src/staged_output.rs](crates/packetcraftr-cli/src/staged_output.rs): separate replacement staging for missing/regular destinations with directory-bound atomic rename; existing artifacts remain no-clobber. | `regeneration_atomically_replaces_existing_regular_files`, `replacement_rejects_directory_and_symlink_destinations`: regeneration preserves mode, rejects directories/symlinks/socket, artifact staging refuses existing files; `new_documentation_uses_normal_creation_permissions` verifies every generated manual/completion matches ordinary creation permissions under the process umask. |
| 47 | [crates/packetcraftr-cli/src/commands/reference/documentation.rs](crates/packetcraftr-cli/src/commands/reference/documentation.rs): render every completion/manual in memory, stage/write/sync all before first publication. | `write_and_sync_failures_leave_all_originals_intact`, `render_failure_and_unsupported_formats_do_not_create_directories`, `actual_render_includes_completions_and_grouped_manuals`: injected stage/write/sync/render failures preserve originals, real rendering produces nonempty unique files. |
| 48 | Same documentation module: errors name operation/destination and already published prefix. | `publication_failure_reports_the_published_prefix_and_destination`, `cancellation_at_publication_reports_destination_and_published_prefix`: second destination failure/cancellation reports first file; its content is committed. |
| 49 | [README.md](README.md): build profiles, native prerequisites, offline examples and generated references; package README and this map. | Reviewed against Cargo feature definitions, release workflow and command-owned examples; documentation-only verification. |
| 50 | Documentation Generate entrypoint validates text format before rendering or filesystem access. | `render_failure_and_unsupported_formats_do_not_create_directories`: all seven unsupported formats leave output directory absent. |

## Validation

All Rust tests used `--locked --offline --lib --no-default-features`:

| Crate / filter | Result |
| --- | --- |
| packetcraftr-core / improvement | 10 passed |
| packetcraftr-core / protocol::message | 39 passed |
| packetcraftr-core / security:: | 26 passed |
| packetcraftr / network_improvements | 7 passed |
| packetcraftr / incomplete_capture_identity_never_reaches_injected_provider | 1 passed (added after original network filter) |
| packetcraftr-netio / network_improvements | 7 passed |
| packetcraftr-cli / command_options | 6 passed |
| packetcraftr-cli / commands::registry::help | 2 passed |
| packetcraftr-cli / documentation | 8 passed under umask 022; new-file permissions case also passed under umask 077 |
| Python test_release_assets.py | 6 passed |
| Python test_build_manifest.py | 11 passed |

Rust formatting (`cargo fmt --all -- --check`) and `git diff --check` passed. Every release source asset and all acceptance-map links were checked for existence. Two implementation workers and
one background reviewer reviewed the batches. Ownership rotated for final cross-review:
parsing reviewed network behavior; network reviewed CLI, packaging and documentation;
the coordinator reviewed parsing. The background reviewer checked all three areas,
compatibility and the 50-item map. Review findings were fixed before completion.

Full feature/platform matrices, release builds and live-network suites are deferred
to CI. No optional prerequisites were installed. The UDP acceptance test uses only
local loopback sockets. Unsupported malformed codec inputs retain the existing
Raw fallback where applicable; no serialized document shapes or existing public
function signatures changed. `Document::validate` and classified route error
variants are additive.

Documentation publication is atomic per file. A later failure can leave a published
prefix, which is included in the diagnostic. Existing artifact publication remains
no-clobber. Existing regular-file permissions are copied to the staged replacement;
symlinks, directories and special files are rejected.
