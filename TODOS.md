# PacketcraftR roadmap and backlog

Planning window: 31 August-11 September 2026 (10 working days, one engineer).

This plan targets one complete user-visible feature. Backlog items are
candidates, not commitments, and should not displace the roadmap unless the
DNS work is blocked or finishes early.

## Two-week outcome

Ship bounded DNS UDP-to-TCP fallback. When an authorized DNS server returns a
validated UDP response with the truncation (`TC`) flag, `packetcraftr dns`
should retry the same query against that server over DNS-over-TCP and report
the complete response.

### Definition of done

- [ ] A matching truncated UDP response triggers at most one TCP fallback in
  that attempt; unrelated, malformed, and non-truncated responses do not.
- [ ] UDP and TCP share the attempt deadline. TCP connect, write, and read
  operations cannot extend the configured operation-duration bound.
- [ ] The TCP path uses a two-byte DNS length prefix, handles partial I/O, and
  rejects zero-length, oversized, incomplete, and malformed first-response
  frames without unbounded allocation. The strict frame decoder rejects bytes
  trailing the declared frame when callers supply them together.
- [ ] The TCP response is validated against the selected server, transaction
  ID, question name, question type, and question class before it is accepted.
- [ ] Resolved TCP destinations pass the same hostname and destination-policy
  checks as the UDP query before connection or data transfer.
- [ ] A complete TCP response ends the operation. A TCP timeout or typed
  failure follows the existing retry limit and produces deterministic final
  outcome precedence.
- [ ] Text, JSON, and NDJSON identify the fallback and the transport of the
  accepted response without representing socket bytes as captured frames.
- [ ] Existing UDP-only behavior remains available through an explicit CLI and
  library option for diagnostics and compatibility.
- [ ] Unit, contract, schema, CLI, and loopback integration tests cover the new
  behavior across affected feature profiles.
- [ ] CLI help, output examples, schemas, public Rust documentation, and the
  `[Unreleased]` changelog describe the shipped behavior.

### Scope guardrails

- No DNS-over-TLS, DNS-over-HTTPS, QUIC, connection pooling, pipelining, zone
  transfers, or arbitrary TCP exchange command.
- No public-network tests. Use loopback servers and deterministic wire
  fixtures.
- Do not move live I/O into `packetcraftr-core`; keep the existing acyclic
  crate dependency direction.
- Do not accept partial records from a truncated UDP response.
- Do not weaken authorization, finite packet/byte/time budgets, response
  correlation, or structured-output completion guarantees.

## Week 1: contracts and core behavior

| Day | Focus | Deliverable |
| --- | --- | --- |
| Mon 31 Aug | Contract and failure semantics | Record the request option, default and opt-out behavior, shared-deadline rule, retry precedence, transport model, output changes, and stable error classifications in tests before implementation. |
| Tue 1 Sep | Mockable TCP boundary | Add the smallest DNS-specific TCP execution seam at the native/workflow boundary, with test doubles for connect, partial read/write, timeout, close, and failure. Keep offline code independent of live I/O. |
| Wed 2 Sep | Bounded DNS-over-TCP I/O | Implement deadline-aware connect/write/read, checked two-byte framing, exact-length reads, and `max_message_bytes` enforcement before allocating the message body. Reuse `dns::decode_tcp_frame`. |
| Thu 3 Sep | Validation and authorization | Re-authorize the selected numeric server address, validate response identity and question fields, and classify malformed, unrelated, truncated-again, network, and timeout results. |
| Fri 4 Sep | Engine integration | Replace terminal UDP truncation with one bounded fallback phase, retain explicit UDP-only mode, integrate retry/final-outcome behavior, and complete focused unit tests. |

### Week 1 checkpoint

- [ ] Mocked success path passes: UDP `TC=1` followed by one complete TCP
  response.
- [ ] Mocked non-fallback paths pass: complete UDP, unrelated UDP, decode
  failure, and UDP timeout.
- [ ] Mocked TCP failures pass: connect failure, short prefix, short body,
  oversized length, trailing bytes, mismatched response, and deadline expiry.
- [ ] Public API and output-contract changes are small enough to finish and
  document in Week 2.

If the checkpoint is missed, cut the compatibility flag or additional text
detail before cutting authorization, bounds, validation, or tests.

## Week 2: product integration and release quality

| Day | Focus | Deliverable |
| --- | --- | --- |
| Mon 7 Sep | Output integration | Represent the attempted and accepted transports in aggregate and progressive output, preserve contiguous NDJSON sequencing, and update text rendering. |
| Tue 8 Sep | Loopback integration | Add deterministic IPv4 loopback tests with a UDP server returning `TC=1` and a TCP server returning a framed response. Cover partial writes, partial reads, timeout, early close, and opt-out behavior. Add IPv6 coverage where the existing test harness supports it. |
| Wed 9 Sep | Contracts and documentation | Synchronize `schemas/` with `examples/documents/`, update CLI help and Rust docs, add a documentation-address example that does not perform live traffic, and update `[Unreleased]`. |
| Thu 10 Sep | Feature-profile verification | Run formatting, targeted tests, workspace tests under affected feature profiles, doctests, Clippy, rustdoc, and the supported feature-matrix script. Fix regressions without broad refactoring. |
| Fri 11 Sep | Review and buffer | Review the complete diff for policy, deadline, partial-I/O, allocation, cleanup, schema, and cross-platform risks. Resolve findings and record exact validation results. |

### Required validation

Run the applicable commands with locked dependencies:

```console
cargo fmt --all -- --check
cargo nextest run --locked --workspace
cargo nextest run --locked --workspace --no-default-features
cargo nextest run --locked --workspace --all-features
cargo test --locked --workspace --all-features --doc
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --locked --workspace --all-features --no-deps
./scripts/check-features.sh
```

## Risk register

| Risk | Mitigation |
| --- | --- |
| TCP fallback accidentally doubles the operation timeout | Derive every TCP operation from the remaining attempt and operation deadlines; test with a controlled clock. |
| A generic socket abstraction expands the change across crates | Keep the first seam DNS-specific and mockable; generalize only after another workflow needs it. |
| TCP bytes do not map to the existing captured-frame evidence model | Model transport and response metadata explicitly; do not synthesize Ethernet/IP/TCP frames. |
| Output changes break schema or NDJSON guarantees | Add contract tests first, update schema and examples together, and retain one terminal complete/error event. |
| TCP fallback bypasses live-operation policy | Authorize the final numeric endpoint before connecting and test denied and re-resolved destinations. |
| Partial I/O or a malicious length prefix causes hangs or allocation spikes | Use exact bounded loops, checked conversions, pre-allocation length checks, and deadline tests. |
| Platform behavior differs | Keep the implementation on portable TCP primitives and run no-default, default, pcap-free, and all-feature checks as applicable. |

## Prioritized backlog

### P1: next useful slices

| Feature | Estimate | Completion slice |
| --- | --- | --- |
| Modern DNS records | 5-8 days | Typed `CAA`, `TLSA`, `SVCB`, and `HTTPS` queries and RDATA, bounded malformed-input tests, text/JSON output, schemas, and examples. |
| Capture metadata inventory | 3-5 days | Add `stats --table capture` for format, sections, interfaces, link types, snap lengths, timestamp resolution, metadata counts, and time range without packet dissection. |
| TLS inventory summaries | 4-6 days | Add bounded `--summary-by` and `--top` views for versions, ciphers, ALPN, SNI, JA3, JA3S, and JA4, including omitted-key counters. |

### P2: full feature iterations

| Feature | Estimate | Completion slice |
| --- | --- | --- |
| Filtered normalized capture export | 6-9 days | Add an explicit normalization mode that can filter and emit PCAPNG while leaving exact source-fidelity rewriting unchanged and reporting discarded metadata. |
| Exchange template sweeps | 8-10 days | Add repeatable typed variation axes, checked Cartesian expansion, `--max-template-packets`, pre-I/O authorization/accounting, and deterministic output. |
| Offline fuzz-case minimization | 6-9 days | Use existing shrink candidates to preserve a stable offline failure classification and emit a minimized reproducible packet document. |
| Cleartext HTTP/1 analysis | 8-10 days | Parse bounded HTTP/1.0 and HTTP/1.1 start lines and headers over existing TCP reassembly; report transactions without body decoding or decompression. |

### P3: deferred candidates

- TLS expert findings for malformed records, handshake gaps, deprecated
  versions, negotiated compression, and fatal alerts.
- Content-sniffed TLS dispatch on TCP ports not selected by protocol bindings
  or `--tls-port`.
- TLS certificate summaries for subject, issuer, validity, and SANs from TLS
  1.2 certificate messages.
- Capture-to-capture TLS fingerprint and parameter comparison.
- Partial TLS hello reporting when one optional extension is malformed.
- `--columns` field selection for concise text output.
- Shared stream-collector abstractions only after another collector confirms
  the common shape.
- Publish crates to a registry only after an explicit owner decision; release
  archives and source builds remain the supported installation paths.

### Explicitly larger than two weeks

- QUIC Initial, TLS-over-QUIC, and DTLS analysis.
- IPv4 and IPv6 fragment reassembly with overlap policy and bounded lifecycle.
- A general active TLS prober or general-purpose TCP exchange workflow.
