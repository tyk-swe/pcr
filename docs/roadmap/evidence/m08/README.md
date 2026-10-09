# M8 service identification evidence

The implementation uses ordinary TCP and connected UDP sockets, including in
native feature builds. Identification does not invoke raw capture, routing,
neighbor discovery or injection. Its applicable platform seam is ordinary socket
I/O, peer identity, timeout/cancellation behavior and bounded response retention;
Windows additionally retains the prefix reported with Winsock `WSAEMSGSIZE`.

The independent conditions are recorded in
[`scanner-corpus.v1.json`](../../../scanner-corpus.v1.json), dataset version 1.4.0.
Core [fixture contracts](../../../../crates/packetcraftr-core/tests/integration/service_identification_contracts.rs)
cover known SSH/HTTP/DNS, unfamiliar services, conflicting products/versions,
misleading claims, malformed replies, truncation, reproducible matching and
bounded documents. Workflow [behavior contracts](../../../../crates/packetcraftr/tests/integration/identify_contracts.rs)
exercise budgets, final endpoint authorization, byte accounting, exclusions,
intensity and portable loopback sockets. Netio
[application I/O contracts](../../../../crates/packetcraftr-netio/tests/integration/application_io_contracts.rs)
exercise partial timeout evidence, peer filtering, UDP prefix truncation and
absence of retransmission. CLI
[contract tests](../../../../crates/packetcraftr-cli/tests/integration/identify_contracts.rs)
cover user invocation, exact bytes, claims, confidence, provenance and publication
contracts against the independently versioned output family.

The [cross-platform acceptance runner](../../../../scripts/test-service-identification.py)
checks unknown/ambiguous machine output as well as bounded, isolated loopback
fixtures for both IP families, with each supported feature profile built
separately. Reports identify
the exercised commit, operating system, architecture, profile and fixture
outcomes. Compilation and unavailable scenarios are not passing runtime evidence.

## Reviewed runtime

Clean implementation and fixtures
`928ad8d555fe8b34abd144083612b54ace0fef1f` passed on 2026-10-09.
[CI run 37989728319](https://github.com/tyk-swe/pcr/actions/runs/37989728319)
completed successfully in all eight jobs, including portable isolation, native
contracts, warnings-denied documentation, decoder oracle and fuzz compilation.

| Platform | Original acceptance report | Profiles | Passed cases | Failed / unavailable |
| --- | --- | ---: | ---: | ---: |
| Linux x86_64 | [linux.json.gz](linux.json.gz) | 5 | 360 | 0 / 0 |
| macOS ARM64 | [macos-arm64.json.gz](macos-arm64.json.gz) | 5 | 360 | 0 / 0 |
| macOS Intel | [macos-x86_64.json.gz](macos-x86_64.json.gz) | 5 | 360 | 0 / 0 |
| Windows x64 | [windows.json.gz](windows.json.gz) | 5 | 360 | 0 / 0 |

Each lane builds portable, default, Layer2, pcap-free Layer3, and all-feature
profiles separately. Eighteen fixture variants run in IPv4/IPv6 and
JSON/NDJSON: 72 cases per profile, 20 profile executions and 1,440 case-runs.
These cover SSH/HTTP claims, root DNS and CHAOS TXT over TCP/UDP, unfamiliar
services/products, conflicting products/versions, deceptive banners, malformed
and truncated replies, response caps, deadlines, exclusions/override and intensity.
Every case executed; no missing profile or unavailable IPv6 path counts as a pass.

The [manifest](manifest.json) records original JSON and gzip SHA-256 digests,
platform/architecture, byte lengths, source artifacts and counts. Archives use
lossless gzip with a zero header timestamp; decompression reproduces the original
CI JSON bytes exactly. Read an archive with, for example,
`gzip -dc linux.json.gz | python3 -m json.tool`.
The [independent audit](independent-audit.json) checks all 1,440 retained cases
against an explicit fixture inventory, including clean revision, build flags,
numeric loopback endpoints, exact requests/responses, outcomes, uncertainty,
confidence, provenance, budgets and timestamps. Its residual limits are recorded:
reports retain result payloads; raw envelope/schema and NDJSON framing assertions
are covered by the CLI conformance tests and acceptance runner.

## Local validation

The reviewed source passed:

- `cargo fmt --all -- --check`.
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`.
- `cargo test --locked --workspace --all-features`.
- `python3 -m unittest discover -s scripts -p 'test_*.py'` (58 tests).
- `python3 scripts/check-architecture.py`.
- `python3 scripts/check-external-consumer.py` (detached offline composition).
- Warnings-denied `cargo doc` with private items for portable, native Layer3,
  and all-feature workspace profiles, matching the CI commands.
- `python3 scripts/test-service-identification.py --require-clean --report target/service-identification/local-final.json` (five profiles, 360 cases).
- Exact release asset staging, binary-generated documentation, tar extraction,
  BUILD-METADATA identity, and `scripts/verify-archive.py` smoke checks using
  an all-feature debug binary, with its build variant explicitly recorded.

These results close M8's applicable ground-truth and ordinary-socket gates.
Broader raw/native inventories and M2/M3/M5/M7 acceptance remain open.
Reports retain work, elapsed time and actual application byte counts; M8 adds
no retained-state or peak-RSS benchmark measurement. Held-out coverage and
confidence evaluation remain M9 work. Versions remain untrusted claims.
