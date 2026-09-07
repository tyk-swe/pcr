# Reviewed improvement backlog

| Baseline | Intake and review | Status |
|---|---|---|
| `9a6803ee0c6b06c8e0c60373a4908c018acd374f` | 9 submissions across four lenses → 7 distinct ideas → 7 kept. Three independent reviewers voted KEEP on every ID (21 KEEP votes); no split votes or review merges. | I12–I18 completed. All task/wave gates and available Linux/MSRV checks passed; exact results and native platform limits are recorded in [PLAN.md](PLAN.md). |

| Convention | Meaning |
|---|---|
| History | I01–I11 are completed. Their original scope and validation remain available with `git show 9a6803ee:BACKLOG.md` and `git show 9a6803ee:PLAN.md`. |
| Dedupe | Features raised 3 ideas, design debt 2, bloat 2, code health 2. Three scan-setting submissions became I13. |
| Effort / impact | S: localized; M: several paths or contracts; L: substantial cross-cutting work. Impact 3: high; 2: moderate; 1: low. Estimates are qualitative. |
| Dependencies | Technical prerequisites only. All seven tasks are independent: one tier. Worker capacity and shared-file scheduling appear in [PLAN.md](PLAN.md). |
| Priority | Highest absolute impact: I12 (3/M). Highest impact for effort: I18, I15, I17 (tied at 2/S). |

## Tier 0 — no dependencies

| ID | Title / lens | Scope | Acceptance criteria | Evidence | Effort | Impact | Deps |
|---|---|---|---|---|---|---|---|
| I12 | Clip child timeouts to the remaining operation budget / Design debt | Bound scan/traceroute batches and live fuzz cases by the remaining outer deadline. | After prior work consumes budget, the next execution receives at most the remaining time; zero/exhausted budgets never invoke it. Execution, evidence validation and response selection use the same effective request and original permit. Deterministic fixtures cover clipping, exhaustion and late evidence. Preserve authorization, pacing/accounting and cooperative provider semantics. | `crates/packetcraftr/src/probe/runner.rs:176`; `crates/packetcraftr/src/scan/executor.rs:63`; `crates/packetcraftr/src/traceroute/executor.rs:80`; `crates/packetcraftr/src/fuzz/run.rs:357`; `crates/packetcraftr/src/dns/engine.rs:503`; `crates/packetcraftr/src/probe/evidence/exact_validation.rs:131` | M | 3 | [] |
| I13 | Remove scan's ineffective batch-size setting / Features, Design debt, Bloat | Delete `--batch-size`, `scan::Limits.batch_size`, its default constant, obsolete checks and wiring. Current execution always uses one correlated probe. | An otherwise valid one-probe request with `max_probes = 1` reaches the fake executor; two probes exceed that ceiling. Prepare the executor for one probe while preserving independent capture/response/evidence limits, correlation and pacing. Remove obsolete batching tests; retain meaningful budget tests. Document API/CLI removal as breaking. | `crates/packetcraftr-cli/src/commands/scan/arguments.rs:110`; `crates/packetcraftr/src/scan/model/request.rs:79`; `crates/packetcraftr/src/scan/plan.rs:25`; `crates/packetcraftr/src/scan/executor.rs:30`; `crates/packetcraftr/src/scan/tests.rs:158`; `crates/packetcraftr-cli/src/system/exchange.rs:20` | M | 2 | [] |
| I14 | Expose registered filter spellings in protocol discovery / Features | Add registry-derived filter metadata to existing protocol detail, using deterministic enumeration of direct/either/bit bindings. | Text and JSON expose `tcp.flags.syn`, `tcp.port`, `udp.port` and direct aliases with their meanings. Explain either-field comparisons, including `!=`. Add optional JSON metadata separately from existing parent `bindings`; preserve existing fields/enums and synchronize schema/examples. Reuse registry data without a new command, grammar or parallel catalog. | `crates/packetcraftr-cli/src/commands/protocols/mod.rs:70`; `crates/packetcraftr-core/src/protocol/builtin/filter.rs:88`; `crates/packetcraftr-core/src/protocol/builtin/filter.rs:102`; `crates/packetcraftr-core/src/registry/lookup.rs:129`; `crates/packetcraftr/src/output/protocols.rs:148`; `crates/packetcraftr-cli/tests/offline_workflows.rs:1486` | M | 2 | [] |
| I15 | Render IPv6 endpoints unambiguously / Features | Replace address/port concatenation in follow, TLS and DNS text with standard numeric endpoint formatting. | Numeric IPv6 renders as `[2001:db8::1]:443`; IPv4 and DNS hostnames keep their existing spelling. Verify representative reports using existing fixtures/rendering paths. Structured output and transport behavior remain unchanged; use `SocketAddr` as existing stats rendering does. | `crates/packetcraftr-cli/src/commands/follow/rendering.rs:67`; `crates/packetcraftr-cli/src/commands/tls/rendering.rs:145`; `crates/packetcraftr-cli/src/commands/dns/rendering.rs:20`; `crates/packetcraftr-cli/src/commands/stats/rendering.rs:31` | S | 2 | [] |
| I16 | Skip structured packet conversions that output discards / Bloat | Construct build/dissect reports only for JSON payloads that consume them; render bytes, names and diagnostics directly elsewhere. | Text/raw/hex and all dissection filter misses avoid packet-document conversion. Preserve exact bytes/text, layer order, diagnostic ownership, errors and input limits; unmatched JSON retains diagnostics with `matched: false` and `dissection: null`, while unmatched non-JSON retains its stderr notice. Existing public conversion APIs remain available. Verify existing output contracts; add no rendering abstraction or benchmark framework. | `crates/packetcraftr-cli/src/commands/build/mod.rs:31`; `crates/packetcraftr-cli/src/commands/dissect/mod.rs:70`; `crates/packetcraftr/src/output/build.rs:37`; `crates/packetcraftr/src/output/dissect.rs:38`; `crates/packetcraftr-core/src/document/convert.rs:10`; `crates/packetcraftr-cli/tests/offline_workflows.rs:1247` | M | 2 | [] |
| I17 | Delete obsolete contract-evolution guarantees / Code health | Correct `schemas/EVOLUTION.md` and output module rustdoc to match current CI and output schemas. | Remove claims of exhaustive example-property coverage, a mandatory patch-only semver gate, and universally closed output objects. Describe retained validation, open aggregate records and strict envelopes/enums/input documents accurately. Preserve the existing compatibility policy; restore no removed checks. Validate documentation against current sources and rustdoc. | `schemas/EVOLUTION.md:18`; `schemas/EVOLUTION.md:21`; `crates/packetcraftr/src/output/mod.rs:7`; `CONTRIBUTING.md:28`; `crates/packetcraftr/tests/published_example_matrix.rs:67`; `.github/workflows/ci.yml:81` | S | 2 | [] |
| I18 | Show read-dissection diagnostics in text / Code health | Render existing diagnostics after each selected frame in `read --dissect` text output. | A diagnostic-bearing capture shows the same code/message in text and NDJSON, with clear source-frame attribution in text. Filtered-out frames emit no diagnostics. Preserve exit behavior, NDJSON placement and byte-oriented output; reuse the existing human renderer and exercise the existing capture fixtures. | `crates/packetcraftr-cli/src/commands/read/rendering.rs:29`; `crates/packetcraftr/src/output/frame.rs:268`; `crates/packetcraftr/src/output/frame.rs:276`; `crates/packetcraftr-cli/src/rendering/human.rs:27`; `crates/packetcraftr-cli/tests/offline_workflows.rs:783` | S | 2 | [] |

| Review refinements incorporated | Decision |
|---|---|
| I12 | Effective timeout also governs evidence validation and response selection; reject zero remaining time explicitly. |
| I13 | Preserve response/capture limits independently of the deleted batching option. |
| I14 | New optional filter metadata has a separate meaning from existing parent bindings. |
| I16 | Skip discarded JSON reports while preserving their diagnostics and public conversion APIs. |
| I17 | Include the independently verified stale closed-object claim in output rustdoc. |

## Completion

I12, I13, I14, I15, I16, I17, and I18 are implemented and validated. Wave 0
retained intentional fail-closed backends, valid empty test bodies, and the
documented decrypt foundation without cleanup changes. Independent reviews
and all wave debt gates passed. [PLAN.md](PLAN.md#final-integration)
records the full four-profile test results and quality checks; native
macOS/Windows checks remain unavailable on this Linux host.
