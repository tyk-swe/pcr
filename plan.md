# Milestone 1 - True NDJSON Streaming for `exchange` and `scan`

## Objective

Replace post-execution NDJSON replay for `exchange` and `scan` with synchronous event emission during execution while preserving output-v1 shapes, aggregate behavior, existing non-streaming APIs, evidence limits, error classifications, and capture cleanup guarantees.

Only source files under `src/` may be changed during implementation. This plan is the sole permitted documentation change.

## Refined Implementation Plan

Key implementation decisions:

- Keep observer failures in generic `ObservedError<E>` types rather than adding them to existing operation errors.
- Derive scan endpoint completion from endpoint indices recorded during `process_batch`, never from probe sequence.
- Preserve scan processing order within each batch: finalized endpoints first, then newly retained undecoded frames.
- Do not migrate `capture --output ndjson`; only the `exchange` code in `src/cli/commands/capture.rs` changes.
- Keep progress observers synchronous and borrowing retained domain objects.
- Do not add a new client module; the exchange progress types fit in `src/client/internal/exchange.rs`.

### Phase 1 - Persistent NDJSON Writer

Modify `src/cli/rendering.rs`.

Add `NdjsonStream<W: Write>` containing a `BufWriter<W>`, command, and next sequence, with methods equivalent to:

```rust
new(writer, command)
emit(event, diagnostics)
emit_terminal(event, diagnostics, stats)
next_sequence()
```

Implementation requirements:

- Construct the existing `output::envelope::Stream::success` envelope.
- Serialize directly using `serde_json::to_writer` without an intermediate JSON `String`.
- Classify `serde_json` I/O errors as exit code 5 and non-I/O serialization errors as exit code 70.
- Write exactly one newline and flush after every record.
- Attach the current sequence to serialization, newline, and flush errors.
- Precompute `next_sequence.checked_add(1)` before writing, but assign it only after serialization, newline, and flush succeed.
- Report overflow as `output::contract::Error::SequenceOverflow` at the current sequence.
- Keep `emit_json_compact` unchanged for unmigrated commands and runtime terminal errors.

### Phase 2 - Borrowed Output Conversions

Modify:

- `src/output/internal/frame.rs`
- `src/output/internal/network.rs`
- `src/output/internal/scan.rs`

Add:

```rust
FrameOutput::try_from_frame_ref(&Frame)
DecodedFrameOutput::try_from_decoded_ref(&DecodedPacket)
ScanPortOutput::try_from_endpoint_ref(&workflow::scan::Endpoint)
```

Refactoring requirements:

- Make `try_from_frame` delegate to the borrowed implementation; its current implementation already clones frame bytes.
- Make decoded conversion share frame, packet-document, layout, and diagnostic mapping. Cloning layout and diagnostics must not alter aggregate serialization.
- Move endpoint mapping out of `ScanCommandResult::try_from_scan` and reuse the borrowed converter there.
- Preserve ICMP port zero, `icmpv4`/`icmpv6` evidence protocol names, transport display names, timestamps, retained frames, evidence order, reasons, and classifications.
- Do not add serialized types or change public output aliases.

### Phase 3 - Exchange Observation API

Modify:

- `src/client/internal/exchange.rs`
- `src/client/internal/client.rs`
- `src/client/mod.rs`

Define the public progress trait, borrowed progress enum, and generic observed error in `client/internal/exchange.rs`, then re-export them through `client::exchange`.

Use these progress semantics:

```rust
Progress::Sent {
    request_index,
    built,
    evidence,
}
Progress::Response { response }
Progress::Unsolicited { response }
Progress::Undecoded { frame }
```

`ObservedError<E>` contains:

- `Operation(client::Error)`
- `Observer(E)`
- `ObserverAndCaptureShutdown { observer, shutdown }`

Keep `Client::exchange` unchanged and implement it through `exchange_observed` with an `Infallible` no-op observer. Exhaustively eliminate impossible observer variants rather than duplicating the execution body.

### Phase 4 - Exchange Emission and Cleanup

Update `ExchangeAccumulator::process` and `drain_available` to accept and propagate a progress observer.

Emission points:

- Emit `Sent` immediately after `sent_at`, `sent_evidence`, and `completed_sends` are updated.
- Emit matched responses only after pushing into `responses`.
- Emit unsolicited and undecoded records only after successful retention and vector insertion.
- Change `retain_unsolicited` and `retain_undecoded` to return `bool`.
- Pass the observer through all three zero-time drain calls and the blocking receive loop.

Use a private active-phase error distinguishing capture I/O from observer failure. On failure while capture is armed:

- Existing I/O failures continue through `error_after_shutdown`.
- Observer failures explicitly call `CaptureGuard::shutdown`.
- Successful shutdown returns `ObservedError::Observer`.
- Failed shutdown returns `ObservedError::ObserverAndCaptureShutdown`.
- No further send, receive, drain, or callback occurs.

Normal shutdown, statistics validation, evidence-loss handling, result construction, and operation error classifications remain unchanged.

### Phase 5 - Exchange CLI Streaming

Refactor only `run_exchange` in `src/cli/commands/capture.rs`.

Branch on NDJSON before calling `Client::exchange`.

For text, JSON, PCAP, and PCAPNG:

- Keep `Client::exchange`.
- Keep aggregate conversion and capture-file sorting/rendering unchanged.

For NDJSON:

- Lock stdout once.
- Construct `NdjsonStream`.
- Construct a synchronous observer borrowing it.
- Call `exchange_observed`.

Map progress as follows:

- `Sent`: checked conversion of request index plus `output::frame::Wire::new(built.bytes.clone())`.
- `Response`: borrowed decoded conversion, request index, and latency.
- `Unsolicited`: borrowed decoded conversion.
- `Undecoded`: borrowed frame conversion.

Attach no diagnostics or statistics to progress records. Any presentation conversion failure must be tagged with `stream.next_sequence()` before returning from the observer.

After successful exchange:

- Emit unanswered indexes in their existing order.
- Destructure the domain result instead of calling `try_from_exchange`.
- Build terminal diagnostics as exchange diagnostics followed by every sent packet's diagnostics in sent order.
- Convert statistics.
- Emit `Complete` with the full unanswered vector through `emit_terminal`.

Error mapping:

- `Operation(error)` becomes `CliError::classified(error).at_sequence(stream.next_sequence())`.
- `Observer(error)` returns that `CliError` unchanged.
- Observer plus shutdown failure uses `error.with_cleanup(shutdown)`.
- Drop the observer and stream before returning an error to `run_entrypoint`.

Delete `render_exchange_stream` and `emit_exchange_record`.

### Phase 6 - Scan Observation API

Modify:

- `src/workflow/scan/model.rs`
- `src/workflow/scan/engine.rs`
- `src/workflow/scan/error.rs`
- `src/workflow/scan_impl.rs`
- `src/workflow/mod.rs`

Add public `Progress`, `ProgressObserver`, `ObservedError<E>`, and `run_observed`. Keep `workflow::scan::run` unchanged and implement it through the observed core with an `Infallible` no-op observer.

Do not add observer variants to `ScanError`. `ObservedError<E>` separately distinguishes:

- `Operation(ScanError)`
- `Observer(E)`

Keep one private engine implementation and one batch loop.

### Phase 7 - Scan Batch Progress

Change `process_batch` to return a private result such as:

```rust
struct BatchProgress {
    completed_endpoint_indices: Vec<usize>,
    undecoded_start: usize,
    undecoded_end: usize,
}
```

During endpoint mutation:

- Locate endpoints with `iter_mut().enumerate()`.
- Record the endpoint index only when `probe.attempt == request.attempts`.
- Preserve probe order in `completed_endpoint_indices`.
- Do not remove or clone endpoints from aggregate state.

For undecoded evidence:

- Record `undecoded_start` before processing batch undecoded frames.
- Record the final vector length afterward.
- The range therefore contains only evidence accepted by both the shared evidence budget and `max_undecoded`.

After `process_batch` releases its mutable borrow:

- Observe completed endpoints in recorded order.
- Observe retained undecoded frames from the recorded range in order.
- Return immediately on observer failure.
- Let the existing next iteration perform its current pre-batch sleep, ensuring failure occurs before any later sleep or execution.

Because final-attempt batches follow address and port schedule order, each endpoint is offered exactly once on successful scans without relying on probe sequence.

### Phase 8 - Scan CLI Streaming

Refactor `run_scan` in `src/cli/commands/scan.rs`.

For text and JSON:

- Keep `workflow::scan::run`.
- Keep `output::scan::Result::try_from_scan`.
- Keep existing renderers unchanged.

For NDJSON:

- Lock stdout once and construct `NdjsonStream`.
- Call `workflow::scan::run_observed` with a CLI observer.
- Convert `EndpointComplete` using `ScanPortOutput::try_from_endpoint_ref`.
- Use the supplied target and `endpoint.address` directly.
- Convert `Undecoded` using `FrameOutput::try_from_frame_ref`.
- Attach no diagnostics or statistics to progress records.

After success:

- Destructure the workflow result without reconverting endpoints or undecoded frames.
- Emit `Complete` using the result's canonical target and resolved-address vector.
- Attach only result diagnostics and converted statistics to `Complete`.

Error mapping:

- Map operation failures with `scan_cli_error(error).at_sequence(stream.next_sequence())`, overriding any probe sequence.
- Return observer `CliError` unchanged.
- Drop the observer and stream before returning to `run_entrypoint`.

Delete `render_scan_stream` and `emit_scan_record`.

### Phase 9 - Cleanup and Validation

Limit implementation changes to the listed `src/` files. Remove obsolete imports and verify by source inspection that:

- There is one exchange execution loop.
- There is one scan execution loop.
- No exchange or scan post-hoc NDJSON replay remains.
- No unrelated NDJSON command uses `NdjsonStream`.
- Existing output event enums, envelopes, schemas, tests, and `#[cfg(test)]` blocks are untouched.

Run only:

```bash
cargo fmt --check
cargo check --all-features --lib --bin packetcraftr
cargo clippy --all-features --lib --bin packetcraftr -- -D warnings
```

Do not run or modify tests, fuzz targets, benchmarks, fixtures, snapshots, golden files, schemas, `Cargo.toml`, or `Cargo.lock` for this milestone.
