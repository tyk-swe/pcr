# Fix the seven verified bug-audit findings

Status: ready-for-human

## Problem Statement

The repo-wide bug audit found seven reproducible defects across capture, live
scan, offline analysis, and machine output. Each can mislead an operator or
prevent an otherwise valid operation:

1. Native capture passes a byte-swapped IPv4 netmask to BPF compilation on
   little-endian hosts. A filter such as `ip broadcast` can miss a directed
   subnet broadcast. In a local libpcap check, a `/24` directed broadcast
   matched with `0xffffff00` and did not match with the generated
   `0x00ffffff`; `/16` behaved the same way.
2. Native capture rejects numeric BPF port ranges such as
   `tcp portrange 80-90` and `udp dst portrange 1000-2000` as though they
   contained symbolic names, although libpcap compiles both expressions.
3. A pipelined packet scan can continue sending after cancellation if an
   embedder supplies the signal through the workflow clock but not through
   the client. A temporary contract repro cancelled the clock signal while
   capture was armed and observed two transmissions before the operation
   failed. The CLI currently gives its clock and client the same signal;
   the public workflow composition permits them to differ.
4. `dns-read` replaces its default DNS service port 53 when an operator adds
   `--dns-port 5353`. The example DNS capture reports one message by default
   and zero messages with that extra option, contrary to the documented
   additive behavior.
5. `dissect` assigns the current wall-clock time to raw hex, file, and stdin
   bytes. Projecting `frame.time_epoch` then reports a time that was never
   captured, and a timestamp filter evaluates against that invented time.
6. The PCAPNG frame mapper can change a frame's original length without
   changing its captured bytes, but its report still says zero frames changed.
   A public API repro changed original length from 2 to 3, wrote the new
   length, and reported `frames_changed: 0`.
7. When a split-form global `--resource-preset` precedes a command, the
   startup context scanner mistakes the preset value for the command. A
   structured parse error for a missing `read` path then reports
   `command: null` instead of `command: "read"`.

## Solution

Make each affected operation report and act on the facts it was given:

- Compile native broadcast filters with the correct IPv4 network mask, and
  accept numeric port-range operands while continuing to block symbolic
  operands that could trigger name resolution.
- Honor the workflow clock's cancellation signal throughout pipelined scan
  execution, including after capture readiness and immediately before any
  neighbor discovery or packet transmission. Stop subsequent work and shut
  down the capture group after cancellation.
- Keep port 53 in `dns-read` when extra DNS ports are requested, without
  charging or processing duplicate port entries.
- Treat raw `dissect` input as timestamp-free. An absent timestamp projects
  as an absent value and a filter that requires it reports the existing
  `packet.timestamp_unavailable` error.
- Count a mapped frame as changed when its captured bytes or permitted
  length metadata changes.
- Preserve the actual command name in JSON and NDJSON startup errors when
  global options with values appear before it.

## User Stories

1. As a capture operator, I want `ip broadcast` to match directed broadcasts on my selected IPv4 subnet, so that relevant frames are not silently lost.
2. As a capture operator, I want `/16` and `/24` interface assignments to produce correct broadcast-filter behavior, so that the filter is reliable across common subnet sizes.
3. As a capture operator, I want native pcap and Npcap backends to receive the same correct network-mask meaning, so that capture behavior does not depend on the backend.
4. As a capture operator, I want a numeric `portrange` filter to be accepted, so that I can capture a bounded service-port interval.
5. As a capture operator, I want source and destination numeric port ranges to work with TCP and UDP qualifiers, so that I can express common BPF filters.
6. As a safety-conscious operator, I want symbolic hosts and services to remain rejected before native filter compilation, so that capture setup does not resolve names unexpectedly.
7. As an embedded scan caller, I want a cancellation signal supplied through my clock to stop a pipelined scan, so that I can rely on the same stop contract as a serial scan.
8. As an embedded scan caller, I want cancellation during capture arming or readiness to prevent any packet transmission, so that a cancelled operation causes no subsequent live traffic.
9. As an embedded scan caller, I want cancellation after one confirmed send to prevent later sends, so that the operation preserves only effects that happened before cancellation.
10. As an embedded scan caller, I want capture resources shut down after cancellation, so that stopped scans do not retain native resources.
11. As a CLI user inspecting DNS traffic, I want port 53 inspected when I add another DNS service port, so that ordinary DNS messages remain in the report.
12. As a CLI user inspecting DNS traffic, I want each configured port considered once, so that repeating port 53 does not duplicate messages or counts.
13. As a machine-output consumer, I want `dns-read` JSON and NDJSON message counts to reflect all configured ports, so that automation does not mistake missing messages for an empty capture.
14. As an analyst dissecting raw bytes, I want absent capture time represented as absent, so that I do not mistake processing time for packet time.
15. As an analyst using `frame.time_epoch` in a filter, I want a timestamp-unavailable error on raw input, so that the filter cannot silently match against fabricated evidence.
16. As a machine-output consumer, I want timestamp projections from raw input to follow the documented missing-value contract, so that downstream data keeps its provenance.
17. As a capture-transform user, I want `frames_changed` to include a changed original length, so that the transform report agrees with the written capture.
18. As a capture-transform user, I want an unchanged frame to remain uncounted, so that the change count is meaningful.
19. As a capture-transform user, I want interface identity and capture time to remain protected, so that correcting change accounting does not loosen transform invariants.
20. As a machine-output consumer, I want parse errors to identify `read` after a preceding resource preset, so that I can associate an error with the attempted command.
21. As a machine-output consumer, I want the same command identity in JSON and NDJSON errors, so that either output mode can be handled consistently.
22. As a CLI user, I want split-form and inline global option values to leave command detection intact, so that option placement does not change error context.
23. As a maintainer, I want public-behavior regressions for all seven defects, so that later refactors cannot silently restore them.
24. As a maintainer, I want the existing machine-output schemas, examples, and release notes updated only where the corrected visible behavior requires it, so that published contracts stay synchronized.

## Implementation Decisions

- Keep each fix with its domain owner: capture parsing and mapping in core,
  native capture validation and BPF compilation in net I/O, scan cancellation
  in the workflow crate, and argument handling, raw dissection, and structured
  error context in the CLI. Core remains independent of native I/O.
- Express the native mask in the integer representation BPF compilation
  actually expects. Verify matching behavior with compiled BPF against packet
  bytes, instead of asserting a particular endian conversion. Preserve the
  existing rule that selects the first IPv4 assignment.
- Extend the numeric-only capture-filter guard to recognize valid numeric
  range operands in `portrange` expressions. Do not admit symbolic host or
  service operands, or add a resolver side effect to validation.
- Carry the workflow's operation cancellation into the existing pipeline
  execution boundary. Check it before active discovery and immediately before
  transmitting each prepared packet, including after capture readiness.
  Retain finite duration, prepared-byte, and evidence budgets and the final
  endpoint and wire-byte authorization. Avoid requiring embedders to wire
  the same signal independently into both client and clock.
- Treat `dns-read` port 53 as the baseline service port and explicit
  `--dns-port` values as additions. Deduplicate before constructing the
  collector; preserve the collector's existing bounded port policy.
- Construct raw dissection frames without a capture timestamp. Keep the
  distinction between absent capture time and a timestamped capture record
  through filtering, field projection, and machine rendering. Preserve
  `packet.timestamp_unavailable` for filters requiring missing time.
- Define a changed mapped frame by a difference in captured bytes or
  permitted frame lengths. Keep the mapper's existing rejection of changes
  to timestamp, interface, link type, and direction.
- Teach startup context scanning to consume both split-form and inline
  `--resource-preset` values while continuing to find the first actual
  command. Preserve JSON and NDJSON envelope shapes and the existing
  classification and exit code of parse failures.
- Record user-visible corrections in `[Unreleased]`. Update machine schemas,
  examples, and CLI contracts only if the corrected values require a
  published-contract change.

## Testing Decisions

- Test observable outcomes and meaningful failure paths. Do not assert
  source layout or a particular endian helper, and do not duplicate the
  same assertion at several layers.
- Use the highest existing seam for each domain rather than introducing a
  new test-only interface: public capture-transform contracts in core,
  BPF compilation against synthetic packets and capture-filter validation
  in net I/O, public pipelined scan contracts with isolated providers in
  the workflow crate, and CLI process contracts for the three CLI defects.
- For the network mask, compile `ip broadcast` with the mask produced from
  `/16` and `/24` interface data and evaluate it on directed-broadcast and
  non-broadcast Ethernet/IPv4 frames. An isolated native capture test may
  supplement this when the Linux launcher is available; ordinary Cargo
  tests must still catch the regression without opening a live device.
- For the numeric-only guard, accept `tcp portrange 80-90` and
  `udp dst portrange 1000-2000`; retain denials for symbolic host and
  service names. Follow the existing capture-filter tests in net I/O.
- For scan cancellation, reuse the isolated sender and capture provider
  pattern in `scan_pipeline_contracts`. Cancel the clock signal during
  capture arming and after one send; assert no later send, typed
  interruption, and capture shutdown. Keep serial scan behavior as a
  comparison where useful, without duplicating its full suite.
- For `dns-read`, use the existing example capture in `dns_read_contracts`
  and process-level tests: default, added port, and repeated port 53 must
  retain the expected one-message result in text and machine modes.
- For raw `dissect`, use process-level projection and filter assertions
  like those in `offline_workflow_contracts` and
  `field_projection_contracts`: missing time is absent in projected
  output, and time filtering returns `packet.timestamp_unavailable`.
- For core mapping, map one PCAPNG frame to unchanged bytes with a changed
  original length, read the output back, and compare its length with
  `frames_changed`. Include an unchanged-frame control case. Follow the
  existing `pcap_rewrite_contracts` and `pcap_fidelity_contracts` style.
- For startup context, use process-level parse errors with the preset
  before and after `read`, in JSON and NDJSON modes, following
  `process_contracts`. Assert command identity as well as exit status.
- Run `cargo fmt --all -- --check`,
  `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`,
  and `cargo test --locked --workspace --all-features` on Linux after the
  fixes. Run relevant focused tests while editing.

## Out of Scope

- New packet protocols, DNS decoders, BPF name resolution, and a broader
  capture-filter grammar redesign.
- A new scan pacing model, policy defaults, packet budgets, or changes to
  which destinations may be authorized.
- Inventing a capture timestamp for raw inputs or changing timestamps
  carried by actual PCAP or PCAPNG records.
- Resolving unrelated audit candidates or changing the public machine-output
  schema beyond what these corrected values require.

## Further Notes

- These seven findings were reproduced during the repo-wide audit. The
  temporary regression probes were removed after verification.
- At the audited revision, the comprehensive Linux format, Clippy, and
  workspace test commands all passed. Native isolated tests were ignored
  because they require the isolated Linux launcher; macOS and Windows
  execution was not available.
- Implement each correction with focused Conventional Commits, and request
  applicable CODEOWNERS review in the eventual PR.

## Comments

- Implementation is on [PR #209](https://github.com/tyk-swe/pcr/pull/209);
  validation is complete and code review is pending.
