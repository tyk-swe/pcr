# Code Quality and Maintainability Plan

Improve documentation and maintainability while preserving public APIs, CLI
output contracts, wire fidelity, authorization checks, and resource budgets.
Follow crate ownership and safety rules in [AGENTS.md](AGENTS.md) and development
profiles in [CONTRIBUTING.md](CONTRIBUTING.md).

## 1. Establish a baseline and fix documentation

Record the revision, toolchain, feature profile, commands, and results before
implementation. This plan does not establish that checks pass.

Review private rustdoc links in core's `analysis/pipeline/mod.rs`,
`analysis/pcap/{mod,writer}.rs`, `registry/validation.rs`, and
`protocol/builtin/mod.rs`. Reproduce diagnostics with the pinned toolchain:

```sh
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --document-private-items --no-deps
```

Resolve links to their intended items, disambiguate module/function names with
`mod@` or `fn@` where needed, and remove redundant explicit targets. Add private
item checks to the existing documentation CI step for all three profiles:
portable, pcap-free, and full native. Retain public documentation checks, since
private-item builds can mask links to items absent from public docs.

## 2. Audit panics and long functions

Collect Clippy diagnostics separately for production and all targets:

```sh
cargo clippy --locked --workspace --lib --bins --all-features -- -W clippy::unwrap_used -W clippy::expect_used -W clippy::too_many_lines
cargo clippy --locked --workspace --all-targets --all-features -- -W clippy::unwrap_used -W clippy::expect_used -W clippy::too_many_lines
```

Classify findings by lint and target, inspecting test cfgs and excluding repeated
compiler summaries. The `unwrap()` calls in workflow `scan/probe.rs`, `dns/tcp.rs`,
and CLI `output/stream.rs` are test-only; their presence under `src/` does not
establish production panic risk.

Prioritize fallible production paths at input and resource boundaries. Use typed
errors that retain their sources; replacing `unwrap()` with `expect()` still
panics. Keep concise test assertions, adding failure messages where useful.
Document justified production panics and scope any lint exceptions narrowly.

Use `too_many_lines` to locate mixed responsibilities, starting with core
analysis, parsing, and reassembly. Extract helpers only when they clarify control
flow or ownership, preserving validation order and errors. Adopt lints only when
the policy is useful and fixes plus justified allowances pass CI's existing
`-D warnings` check. Workspace `warn` lints would otherwise fail CI immediately.

## 3. Preserve process-test coverage across profiles

Review the four Linux cfg attributes in CLI tests `cancellation_contracts.rs`,
`process_contracts.rs`, and `normalized_capture_contracts.rs`. Their requirements
include `/proc`, signals, util-linux `script`, and `/dev/full`, independently of
native networking features. Netio's build-script cfgs are package-local; the CLI
cannot use them without explicit wiring.

Replace direct OS gates with capabilities describing the tests' requirements.
Use runtime facility checks where compilation is portable. Where compile-time
selection is necessary, add and register cfgs in the consuming package's build
script using Cargo's **target** metadata, not the build host's OS or facilities.
Keep native provider selection in netio.

Report unsupported environments explicitly. Required Linux CI scenarios must
execute and fail on missing prerequisites, rather than return early and appear
to pass. Preserve coverage in full-native, portable, and pcap-free builds, and
verify affected macOS and Windows behavior through platform CI.

## 4. Refactor only demonstrated responsibility boundaries

Evaluate these candidates; file length alone does not justify a split:

| Module under `crates/` | Boundary to evaluate |
|---|---|
| `packetcraftr-core/src/protocol/application/tls/parse.rs` | Record and handshake parsing |
| `packetcraftr-core/src/analysis/reassembly/ip/engine.rs` | Fragment merge planning and state updates |
| `packetcraftr/src/dns/tcp.rs` | Transport implementation and unit-test fixtures |
| `packetcraftr-netio/src/neighbor/resolver.rs` | Resolution state and request construction |
| `packetcraftr-cli/src/output/stream.rs` | Encoding, sink lifecycle, and unit tests |

Inspect production and test code separately. Keep types and behavior together,
helpers private, and public paths stable. Do not claim compile-time improvements
without measurements.

Preserve the integration-test layout unless clean, incremental, and focused
compile measurements justify a change, as required by CONTRIBUTING.md. If a
reorganization is justified, group by observable contract and preserve focused
invocation, test discovery, feature coverage, and failure assertions. Each new
top-level integration-test file creates another binary.

Keep test support local to its owning crate and consolidate only demonstrated
duplication. Shared support may need scoped `dead_code` allowances when compiled
into multiple test binaries; remove code or allowances only after checking all
consumers.

## 5. Keep maintenance policy proportionate

- Fill useful public API documentation gaps; consider `missing_docs` in selected
  modules before a workspace-wide rollout.
- Revisit dependency exceptions during upgrades. `deny.toml` already documents
  allowed duplicates; reduce them when compatible and retain justified cases.
- Use existing CI evidence. Add metrics tooling only for a recurring decision
  that existing output cannot support.

## Validation and completion

Keep documentation fixes, lint changes, and refactors in focused changes. For
code changes, run affected crate tests and relevant feature profiles. Before
integrating broad refactors, run these Linux checks with `libpcap-dev` installed:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 scripts/check-architecture.py
```

Run public and private rustdoc checks for the three existing CI documentation
profiles. For gating changes, use the exact portable and pcap-free test commands
in [.github/workflows/ci.yml](.github/workflows/ci.yml), plus affected platform CI.
Run `cargo deny --locked check` if dependencies change.

Complete each selected change when its checks pass, adopted lints have justified
exceptions, required process tests execute, and observable behavior and crate
boundaries are preserved. Record exact results and unavailable checks in each PR
and request applicable CODEOWNERS review. Document user-visible fixes in
`[Unreleased]`; public contract changes require separate scope and synchronized
schemas, examples, CLI tests, and release assets.
