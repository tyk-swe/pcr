# Repository Guidelines

## Read-First Files

Start here before editing anything substantial:

- `Cargo.toml`: authoritative feature graph. `default = ["traceroute"]` and
  `experimental = ["scan", "fuzz", "daemon", "repl", "metrics"]`.
- `src/lib.rs` and `src/main.rs`: crate entry points and top-level module map.
- `src/cli/mod.rs`, `src/cli/commands.rs`, and `src/cli/options.rs`: full CLI
  surface, global `--dry-run`, feature-gated commands, and path-bearing flags.
- `src/app/cli_mapping.rs`: the main CLI-to-engine mapping layer.
- `src/engine/core.rs` and `src/engine/oneshot.rs`: command dispatch, dry-run
  branching, rules loading, privilege checks, and one-shot send flow.
- `src/network/io/sender/mod.rs` and `src/network/io/listener/mod.rs`: live
  transmission and listener entry points.
- `src/rules/mod.rs`, `src/rules/engine/mod.rs`, and `src/rules/send.rs`: rule
  loading, execution, and templated send behavior.

## Feature Matrix

| Surface | What It Enables |
| --- | --- |
| always on | `send`, `dry-run`, and `dns-query` |
| `traceroute` | `traceroute` command, traceroute domain types, and traceroute network helpers |
| `scan` | `scan` command plus `tcp-syn`, `tcp-fin`, `tcp-null`, `tcp-xmas`, `tcp-ack`, `sctp-init`, `icmp`, `udp`, `arp`, and `ndp` |
| `fuzz` | `fuzz` command and fuzz engine |
| `pcap` | `listen` command, reply capture, `--pcap-save`, and `--pcap-write` |
| `daemon` | `daemon` command, daemon runtime, and Unix control socket support |
| `repl` | `interactive` command; also pulls `pcap`, `scan`, and `traceroute` |
| `metrics` | `--metrics-json`, `--prometheus-bind`, and `--allow-public-metrics` |
| `experimental` | convenience bundle for `scan`, `fuzz`, `daemon`, `repl`, and `metrics` |

## Safe Commands vs Privileged Commands

Safe verification commands:

- `scripts/verify-agent.sh quick`
- `scripts/verify-agent.sh matrix`
- `scripts/verify-agent.sh full`
- `cargo run -- --help`
- `cargo run --features experimental -- --help`

Dry-run-safe runtime commands:

- `packetcraftr dry-run ...`
- `packetcraftr --dry-run send ...`
- `packetcraftr --dry-run daemon ...`
- `packetcraftr --dry-run listen ...`
- `packetcraftr --dry-run traceroute ...`
- `packetcraftr --dry-run scan ...`
- `packetcraftr --dry-run fuzz ...`
- `packetcraftr --dry-run dns-query ...`

Dry-run still parses input, can resolve destinations, can read `--rules`, and can
start logging or telemetry if those options are present.

Commands that may require root or `CAP_NET_RAW`:

- live one-shot send when using layer-2 overrides, raw TCP/UDP/ICMP/ICMPv6, or
  forced layer-3 transmission
- live `traceroute`
- live `scan`
- live `fuzz`

Other side-effecting commands:

- live `dns-query` does network I/O but does not use raw sockets
- `listen` and reply capture may need host-specific capture permissions
- live `daemon` can daemonize and bind a Unix control socket
- any command using `--prometheus-bind` can open an HTTP listener during bootstrap

## Runtime Side Effects And Generated Artifacts

- REPL history is stored at `$PACKETCRAFTR_HOME/repl_history`, or
  `.packetcraftr/repl_history` when the environment variable is unset. The
  directory is created on demand, history is loaded at startup, and saved on exit.
- `--log-file <path>` creates parent directories and opens the file in
  create-and-append mode during bootstrap. A dry-run one-shot command can still
  create or append to this file.
- `--pcap-save <path>` creates parent directories and writes captured packets.
  `--pcap-save`, `--show-reply`, or `--filter` can implicitly enable the listener.
- `--pcap-write <path>` is `pcap`-gated. A live send creates parent directories,
  opens a pcap savefile, and records transmitted frames.
- `--metrics-json <path>` is `metrics`-gated. A live send creates parent
  directories and overwrites the JSON snapshot before transmission.
- `--rules <path>` is read from disk by one-shot and daemon flows.
- `--control-socket <path>` is daemon-only. Preflight binds and removes a test
  socket first; the live daemon then binds the real socket, uses mode `0600`,
  accepts only same-UID peers, and removes the socket during cleanup.
- `--prometheus-bind <addr>` starts the Prometheus exporter during bootstrap.
  Non-loopback binds are rejected unless `--allow-public-metrics` is set, and a
  dry-run one-shot command can still bind the metrics port.

## Verification Workflow

Use the pinned Rust toolchain in `rust-toolchain.toml`. `clippy.toml` keeps the
MSRV at `1.96`, and `rustfmt.toml` enforces Rust 2021, Unix newlines, and a
100-column width.

Use this order for non-trivial work:

1. `scripts/verify-agent.sh quick`
2. Make the first structural pass.
3. `scripts/verify-agent.sh quick`
4. Make feature-surface or CLI mapping changes.
5. `scripts/verify-agent.sh matrix`
6. Finish with `scripts/verify-agent.sh full`

Script modes:

- `quick`: `cargo fmt --check` and `cargo test`
- `matrix`: `cargo test --no-default-features`, `cargo test`, `cargo test --features daemon`, and `cargo test --features experimental`
- `full`: `cargo clippy --all-targets --all-features -- -D warnings`

## Common Change Recipes

1. Add or rename a one-shot flag: update `src/cli/options.rs`, the matching file
   under `src/cli/request/`, `src/app/cli_mapping.rs`, the corresponding
   `src/domain/spec/*.rs` builder, and inline tests.
2. Add or rename a command-specific flag: update `src/cli/commands.rs`, the
   relevant mapping file under `src/cli/request/`, `src/domain/command.rs`, and
   the matching branch in `src/engine/core.rs`.
3. Change dry-run or live send behavior: read `src/engine/oneshot.rs`,
   `src/engine/send.rs`, `src/network/io/sender/mod.rs`, and `src/output/report.rs`
   together before editing.
4. Change daemon or rules behavior: read `src/app/daemon_bootstrap/mod.rs`,
   `src/engine/daemon/mod.rs`, `src/engine/daemon/control.rs`,
   `src/rules/engine/mod.rs`, and `src/rules/send.rs` together.
5. Change logging, pcap, or metrics outputs: read `src/domain/spec/logging.rs`,
   `src/util/logging.rs`, `src/app/telemetry/mod.rs`, `src/util/telemetry/mod.rs`,
   `src/network/io/sender/executor/recorder/writer/mod.rs`, and
   `src/network/io/listener/capture.rs` together.
6. Add feature-gated behavior: update `Cargo.toml`, the gated module declaration,
   the CLI surface, the engine dispatch path, and run
   `scripts/verify-agent.sh matrix`.

## Known Hotspot Files

- `src/domain/policy.rs`: behavior-heavy traffic classification and policy logic.
- `src/engine/core.rs`: central command dispatch and dry-run/live branching.
- `src/engine/oneshot.rs`: one-shot send flow, rules startup triggers, and reply
  listener behavior.
- `src/app/cli_mapping.rs`: most CLI behavior changes become engine wiring changes here.
- `src/tools/traceroute/utils.rs`: high-density protocol parsing and probe matching.
- `src/tools/scan/common.rs`: shared scan parsing and validation.
- `src/network/io/listener/capture.rs`: actual capture startup, packet loop, and
  pcap artifact writing.
- `src/network/io/sender/executor/mod.rs` and
  `src/network/io/sender/executor/recorder/mod.rs`: transmission execution and
  send-side recording.
- `src/rules/engine/mod.rs` and `src/rules/send.rs`: rule loading, schema
  handling, and templated send output fields.

Unless a task explicitly calls for refactoring, keep changes around these files
small and well-scoped.

## Project Structure & Module Organization

`packetcraftr` is a Rust 2021 CLI/library crate. `src/main.rs` delegates to
`packetcraftr::run_cli`, while `src/lib.rs` exposes the application entry point.

- Keep CLI parsing in `src/cli`.
- Keep CLI-to-request mapping in `src/cli/request`.
- Keep bootstrap and dispatch wiring in `src/app`.
- Keep domain models and packet specs in `src/domain`.
- Keep orchestration in `src/engine`.
- Keep packet I/O and protocol logic in `src/network`.
- Keep user-facing commands in `src/tools`.
- Keep rule automation in `src/rules`.
- Keep output formatting in `src/output`.
- Keep shared helpers in `src/util`.

Tests are embedded next to the code under `mod tests`; there is no top-level
`tests/` directory. When a module has children, prefer `foo/mod.rs` over mixed
`foo.rs` plus `foo/` layouts.

## Coding Style & Naming Conventions

Follow existing Rust naming: `snake_case` functions and modules, `PascalCase`
types, and `SCREAMING_SNAKE_CASE` constants. Preserve feature gates such as
`scan`, `fuzz`, `daemon`, `repl`, `pcap`, and `metrics` when adding optional
behavior.

Prefer small structural changes over broad refactors. Reuse existing mapping,
planning, and formatting helpers before introducing new ones.

## Testing Guidelines

Add tests in the same file as the behavior they cover, under `#[cfg(test)] mod
tests`. Use `#[test]` for synchronous logic and `#[tokio::test]` for async engine
or tool flows.

Prefer deterministic unit coverage for parsing, validation, planning, and output
formatting. Avoid tests that require live network access unless they are
explicitly feature-gated and isolated.

## Commit & Pull Request Guidelines

Use lowercase type labels in parentheses followed by a colon and imperative
summary, for example `(feat): add DNS retry policy`, `(test): expand traceroute
coverage`, or `(docs): update contributor guide`. Common types are `(feat)`,
`(fix)`, `(test)`, `(docs)`, `(refactor)`, and `(chore)`.

Keep commits focused on one change, and use the same format for PR titles. PR
descriptions should explain the behavior change, list commands run, mention
affected feature flags, link related issues, and include terminal output or
screenshots only when CLI behavior changes.
