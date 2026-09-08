# Migrating to 0.5.0-beta.3

This note covers the changes between 0.5.0-beta.2 and 0.5.0-beta.3. No legacy
reader or facade was restored; update call sites as described below.

- Output envelopes use `packetcraftr.output/v2`. NDJSON discriminators live at
  the root: `jq 'select(.event == "session") | .result.client.ja4'`. One
  `complete` or `error` record terminates a writable stream. Packet documents
  remain `packetcraftr.packet/v1`.
- Import packets and offline analysis from `packetcraftr_core`, native resources
  from `packetcraftr_netio`, workflows and policy from `packetcraftr`, and CLI
  representations from `packetcraftr_cli::output`. The CLI crate's Rust types are
  beta APIs; their stability is separate from the versioned JSON contract.
- Operation admission is `packetcraftr::policy::Policy::authorize`. Final wire
  authorization and separately authorized DNS TCP fallback remain required.
- The owning TLS collector now validates on construction:
  `let collector = packetcraftr_core::analysis::tls::Collector::new(limits)?;`.
  DNS `unpredictable_transaction_id()` and `unpredictable_source_port()` also
  return `Result`; propagate system entropy failures. Explicit request identities
  retain deterministic retry rotation.
- `--max-tls-sessions` limits concurrent tracked TLS state. Use the independent
  `--max-output-sessions` to limit aggregate JSON retention (zero keeps no rows).
  Text and NDJSON still emit every selected session. Library stats callers can
  choose `Collector::for_table(interval, Table::Protocols)` or another table;
  `Collector::new(interval)` still collects all tables.
- Conversation indices identify capture-global **scoped tuples**, including tuple
  reuse, and are assigned before filtering. Scope IDs and capture-wide interface
  indices are run-local. Conversation rows and TLS/follow results expose interface
  and ordered encapsulation metadata. Follow chunks identify
  `direction_generation`: group it with direction when interpreting consecutive
  byte ranges. An eviction boundary is not proof of a new TCP handshake; raw
  follow output remains an explicitly unframed concatenation.
- `packetcraftr::scan::Batch` now owns one `probe`; executor implementations
  read `batch.probe` instead of a one-element `batch.probes` vector. Probe order,
  upfront budgets and final exact-wire checks are preserved.
- `--max-flows` limits cumulative distinct conversations per transport; expiry
  does not reclaim their indices. `--max-scope-bytes` separately bounds retained
  scope metadata. Clock reports preserve capture timestamps and expose regressions
  and the largest forward step. I/O bucket `origin` is distinct from the minimum
  matched timestamp; `underflow_frames` counts earlier frames clamped to bucket 0.
- NDJSON records have a 16 MiB encoded limit including the newline. A record that
  exceeds it is refused before publication; an error terminal is emitted if the
  sink remains writable. Arbitrary `Serialize` implementations are synchronous;
  the writer timeout does not preempt them. `with_deadline` bounds lock and
  bounded-writer waiting by the remaining operation budget; max-duration NDJSON
  commands use it. Capture/exchange response-window timeouts retain their
  distinct meaning. The original encoder handle can report an error after a
  publication deadline; cleanup/error output has its own finite writer wait.
- Commands with cooperative cancellation handle Ctrl-C and, on Unix,
  SIGTERM/SIGHUP: the first requests
  cooperative cleanup, the second exits immediately. Cancellation exits 130 and
  reports `io.cancelled` when it is the primary failure. Already completed sends
  and earlier records remain evidence. Pending reads/provider calls and callback
  destructors cannot all be preempted; force exit cannot promise a terminal record.
  Libraries install no signal handlers. Share `budget::Cancellation` with
  analysis `Options`, `clock::CancellableClock`, and `Client::with_cancellation`.
  Capture readers accept `with_cancellation` and check packets, metadata and
  EOF; offline fuzzing checks between cases in every output format. Build,
  dissect, protocols, interfaces, routes and plan retain OS signal termination.
- Binary raw/PCAP/PCAPNG output refuses an interactive terminal unless
  `--force-binary-stdout` is supplied. Redirection and pipes retain exact bytes.
- `native-interfaces` and unused `decrypt` are removed. Choose offline
  (`--no-default-features`), pcap-free (`--no-default-features --features
  native-layer3`), or full native (`--all-features`). Default features provide
  passive native routes/interfaces; they do not enable every live backend.
