# September 2026 engineering review dispositions

The four-crate ownership model is preserved. This pass addresses concrete
correctness, resource, observability and validation work; optional capabilities
and abstraction-only changes are explicitly separated below. The review was
checked against the working repository rather than treated as proof that every
suggestion described a defect.

| ID | Disposition |
| --- | --- |
| R01 | Fixed. TLS counts distinct visible indices independently of active-state eviction; the filtered `[1,0,1,0]` regression includes reverse direction and an indexed-flow ceiling. |
| R02 | Fixed. Help uses root `.event`; published and real TLS output exercise that predicate. |
| R03 | Fixed. Removed the superseded decrypt addition and stale source-layout-test claim. |
| R04 | Fixed. Benchmarks fail on reader errors and assert 100 frames / 101 post-header PCAPNG records. Initial reader construction consumes the section header. |
| R05 | Hardened. Explicit fallible getrandom system entropy, original failure source, deterministic injection, and unchanged explicit identities. Retry rotation is documented without claiming independent entropy. |
| R06 | Added run-local scope/interface/encapsulation metadata to conversations, follow and TLS, with small published VNI fixtures. |
| R07 | Documented tuple versus connection identity; follow chunks now identify per-direction delivery generations across reuse/eviction. TLS retains its distinct session IDs. |
| R08 | Added capture-global clock evidence and explicit high-water policy; regressions/outliers do not rewrite timestamps. |
| R09 | Added stable I/O origin and underflow counts, with a 100/90/101 capture example. |
| R10 | Deferred optional timestamp-less analysis. No requested workflow justifies a new mode and filter/expiry contract in this maintenance pass. |
| R11 | Documented input selection versus completed-session selection at the public options owner and in migration/resource examples. |
| R12 | Implemented selected core stats collection and equality/empty-unselected-table regression; shared totals remain single-owned. |
| R13 | Added a simultaneous-allocation model and a reproducible workload/RSS/allocator measurement suite. No process-RSS ceiling is claimed. |
| R14 | Added an independently enforced conservative retained scope-byte charge, accounting for path capacities and shared output paths, with exact/one-byte-short tests. |
| R15 | Split `--max-output-sessions` from active `--max-tls-sessions`; output omission evidence remains intact. |
| R16 | Scan planning now validates totals and yields batches lazily in the original address/attempt/endpoint order. |
| R17 | Implemented a single-probe scan batch value. The shared private runner operates on pacing/deadline controls; traceroute retains its multi-probe shape. Scan has no empty/multi-probe input branch or one-element probe vector. |
| R18 | Added a 16 MiB encoded NDJSON record ceiling using bounded preparation, including escaping/newline bytes. Aggregate JSON already serializes through a fixed-size buffer; retained domain objects remain governed by their own limits. |
| R19 | Added separate timing samples and `with_deadline` publication. Max-duration CLI commands pass the remaining budget through lock waiting, post-serialization checks and bounded writer waits; startup retains an error-reporting owner. Tests distinguish all three phases and cleanup retention. |
| R20 | Added runtime samples for effective capacity, active workers, rejected admissions and timed-out work retaining permits. Cleanup ownership is unchanged. |
| R21 | Kept documented clamping and the effective-capacity getter; snapshots also report effective capacity. A second constructor is unnecessary for this optional API request. |
| R22 | Added explicit cancellation signals through analysis, pacing, live client boundaries, capture polling and publication waits. The cancellation follow-up also checks capture copying/selection at record and EOF boundaries and offline fuzzing between cases, with SIGINT/SIGTERM process regressions. Commands without cooperative checks retain OS signal termination. |
| R23 | Kept canonical domain counters/error codes and documented machine-readable distinctions between empty, filtered, evicted, omitted and incomplete results. No competing generic loss taxonomy was introduced. |
| R24 | Deferred the optional pollable stdin adapter. Generic reads remain cooperative; a blocked read may require the deliberate second-interrupt force exit. No abandoned-reader-thread pool was added. |
| R25 | Preserved the four directional crates and native unsafe-code fence. |
| R26 | Extracted exact IP wire reconstruction into its own private module; admission, range mutation and recorded-charge release remain together in the stateful engine. |
| R27 | Reviewed/preserved the existing explicit UDP attempt / separately authorized TCP continuation / accepted-response path. Added cancellation checks without a generic workflow rewrite. |
| R28 | Documented generation/terminal ownership invariants beside `Tracked`, with a terminal charge-release assertion exercised by existing transitions and new schedule fuzzing. |
| R29 | Kept small modules that own real types, clap groups or platform invariants. No file-count cleanup or forwarding facade was added; the IP split has a concrete responsibility. |
| R30 | Removed the `ScopedFlowKey as FlowKey` aliases in expert analysis and deduplication, retaining the scoped name in signatures. |
| R31 | Reviewed owning-crate paths and documented the CLI output Rust/JSON stability boundary. No facade mirrors were restored or public helpers added only for sibling imports. |
| R32 | TLS construction now validates before input. Deliberate positive small library byte budgets remain supported and documented separately from the CLI's one-direction floor. |
| R33 | Deferred fixture/test-binary reorganization. Existing focused Cargo targets remain available; compile timing, not file count, is the stated prerequisite for later consolidation. |
| R34 | CI restores, minimizes, bounds and republishes per-target corpora. Contributor instructions require minimized fixed-crash fixtures in ordinary tests. |
| R35 | Pinned fuzz nightly, recorded failure provenance, and separated 30-second smoke from bounded 300/900-second manual campaigns. |
| R36 | Added full UDP/TCP DNS messages, near-valid wrong-ID/question mutations, and the public pure response classifier with wrong source/destination addresses and ports. All identities are deterministic and no live traffic is used. |
| R37 | Added structured TCP and TLS schedule targets; kept existing byte targets and the already structured IP push/expire/flush target. |
| R38 | Added owned Windows buffer tests for short/misaligned nodes, cyclic traversal, string alignment/termination and range overflow. Provider pointers are only dereferenced under their existing ownership/bounds invariants. |
| R39 | Added an exchange phase/fault matrix covering startup, readiness, partial send, receive, shutdown, cancellation and callbacks. Existing policy tests cover denial before discovery. |
| R40 | Added a pinned TShark oracle over curated network/transport/DNS vectors and TLS JA3, with explicit physical-fragment semantic allowances. |
| R41 | Added generated multi-section/endian/unknown-metadata rewrite and physical-selection properties. Existing normalization tests retain their separate loss contract. |
| R42 | Added scope byte-boundary, filtered stream/eviction, cancellation-before-input and output expansion boundaries alongside existing coupled IP/TCP/cascade budget regressions. |
| R43 | Added generated whole-encoder trace properties for contiguous sequence, consistent command/schema, one terminal and rejection of post-terminal data. Existing command integration/schema tests remain authoritative for payloads. |
| R44 | Added every-byte data/terminal write and flush failures beside existing blocked-writer tests; failed streams cannot acknowledge completion or retry publication. |
| R45 | Existing tests already accepted nested extensions and rejected forbidden envelopes/invalid known fields. Added explicit legacy event-placement and unknown-root-event rejection. |
| R46 | CI now executes deterministic all-feature netio/CLI contracts on macOS and Windows. Local cross-compilation is distinguished from runtime execution. |
| R47 | Added tests of the exact native-layer3 pcap-free feature set, retaining the independent build/linkage check. |
| R48 | Added an opt-in loopback-only namespace exchange suite with OS/version/packet evidence. This environment forbids namespace creation; hardware Layer 2/neighbor and other-OS live tests remain dedicated-lab work. |
| R49 | Release preflight reruns the existing locked advisory/license/source/duplicate policy. No advisory exception was added. The exact nix duplicate exception documents rtnetlink versus ctrlc requirements. |
| R50 | Added explicit main CI, fuzz and coverage timeouts; release/dependency jobs already had bounds. |
| R51 | Release archives gain a build manifest containing commit, target, compiler, feature variant, version and executable digest, verified after extraction. Normal source builds do not probe Git. |
| R52 | Published the actual release runtime baselines and native dependency assumptions; added an Ubuntu 24.04 container smoke, with no libpcap installed for pcap-free. |
| R53 | Documented risk-based coverage review for unsafe views, rejection, parser limits and cleanup. Kept the optional coverage workflow without a percentage gate. |
| R54 | Added complete CLI workflow measurements for read, follow, TLS and selected/filtered stats, file/pipe and supported aggregate/stream formats; setup and output sink are explicit. |
| R55 | Replaced the tiny RSS demo with generated high-cardinality, segment, retransmission, fragment, scope and TLS-gap workloads; allocator profiles are explicitly separate from RSS. |
| R56 | The workload suite records several cardinalities, input/frame counts, elapsed time and peak memory, including limit failures. No shared-runner performance thresholds were added. |
| R57 | Measured and removed redundant protocol-name allocations using borrowed lookup; the 8,192-flow output is identical and allocator calls fell by 16,382. Larger decoder/layout costs were left for separate evidence-led work. |
| R58 | Clarified serial rate ceilings, retained conservative upfront duration validation, and exposed planned timeout/pacing duration plus achieved rate in text reports. JSON has planned duration and the underlying count/elapsed statistics. |
| R59 | Added binary-terminal refusal and the narrow `--force-binary-stdout` override, with a pseudo-terminal regression. |
| R60 | Placed offline, pcap-free and full-native build recipes together beside installation instructions. |
| R61 | Help and remediation now distinguish physical input, cumulative indices, concurrent state, retained output, scope bytes and wire budgets. Filters are no longer suggested as a remedy for pre-filter costs. |
| R62 | Deferred optional catalog expansion. No second handwritten protocol-support matrix or unsupported QUIC/decryption promise was introduced. |
| R63 | Selected development version 0.5.0-beta.3, synchronized owning-crate versions/locks, and added a concise end-state migration note. Tagging/publication remains a separate release action. |
| R64 | Preserved product scope: no plugin framework, daemon/UI, async conversion, compatibility aliases, speculative protocols or unused crypto features. |

## Validation

Local validation on September 7, 2026 used the pinned Rust 1.98.1 toolchain on
Linux with libpcap development files installed:

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed. |
| `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | Passed. |
| `cargo test --locked --workspace --all-features` | 1,109 passed across 82 suites after the cancellation follow-up; zero failed or ignored. |
| `cargo test --locked --workspace --no-default-features` | 1,055 passed across 81 suites; zero failed or ignored. |
| `cargo test --locked -p packetcraftr-cli -p packetcraftr-netio --no-default-features --features packetcraftr-cli/native-layer3,packetcraftr-netio/native-layer3` | 357 passed across 24 suites; zero failed or ignored. |
| `cargo build --locked -p packetcraftr-cli --no-default-features --features native-layer3` and `ldd target/debug/packetcraftr` | Built successfully; no libpcap dependency. |
| `cargo check --locked --workspace --all-targets --all-features --target x86_64-pc-windows-gnu` | Passed cross-compilation, including test targets. This does not execute Windows tests. |
| `cargo check --manifest-path fuzz/Cargo.toml --locked` and fuzz rustfmt | Passed. |
| `cargo deny --locked check` | Advisories, bans, licenses and sources passed. |
| `cargo deny --locked --manifest-path fuzz/Cargo.toml check advisories` | Passed. |
| `cargo bench --locked -p packetcraftr-core --bench benchmarks -- capture_read --test` | Both complete-reader benchmark smoke checks passed. |
| Independent Draft 2020-12 schema/example validation | Both schemas valid; all 90 JSON examples passed (87 output/v2 and three packet/v1). |
| Pinned TShark 4.6.4 decode oracle | 17 curated physical frames and TLS JA3 matched under the documented fragment allowances. |
| Structured fuzz smoke with the August 28 nightly | DNS: 17,885 runs; TCP schedule: 43,977; TLS schedule: 8,219. Each completed in six seconds without a crash; these are smoke checks, not coverage campaigns. TCP corpus minimization completed with 229 retained inputs. |
| CLI/manual boundary checks | Fixture and real TLS jq predicates matched; SIGINT/SIGTERM produced cancellation exit 130 and contiguous error traces; a second interrupt exited a blocked read. Pseudo-terminal binary refusal is also covered by the Rust process tests. |
| Measurement tools | 56 workflow runs: 50 completed and six returned the intended flow/scope policy errors. Recorded binary digests identify the measured builds; the allocation comparison retained byte-identical output with 16,382 fewer calls. |
| Build manifest and supporting files | Valid metadata accepted and a modified digest rejected; Python/shell syntax, workflow YAML parsing and `git diff --check` passed. |

The cancellation follow-up reran formatting, strict workspace Clippy, the full
all-feature workspace suite, and focused reader/fuzz/signal regressions. Other
profile, platform and measurement results above are from the initial review pass.

The isolated native suite could not enter its network namespace because this
environment rejects `/proc/self/uid_map` writes with `Operation not permitted`.
It was not redirected onto host interfaces. macOS/Windows runtime tests, hardware
Layer 2/neighbor tests, the Ubuntu runtime container and GitHub CI/release jobs
were not executed locally. Their workflow/script additions are not runtime
evidence. No tag or release was published.
