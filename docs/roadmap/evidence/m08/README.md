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

The archives below replace the historical reports with corrected inventory 1.4.0
conditions: exact known versions, the misleading HTTP claim, and separate
nginx/Apache fields with distinct provenance indices.

Clean implementation and fixtures
`99a9cf23216eb490892c0b6659e303d1a0b02c3d` passed on 2026-10-10.
[CI run 38009601998](https://github.com/tyk-swe/pcr/actions/runs/38009601998)
completed all seven applicable jobs, including portable isolation, native
contracts, warnings-denied documentation, decoder oracle and fuzz compilation.
The isolated native launcher is skipped for pull requests.

Reports identify CI's PR merge checkout
`103a1594fd8d94262404bd73b5aee94494877690`. Its tree is identical to the
implementation tree. The manifest retains both revisions, the base revision and
tree identities rather than conflating a PR head with the checkout SHA.

| Platform | Corrected acceptance report | Profiles | Passed cases | Failed / unavailable |
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

Reviewed source `70a9c66eded90db44930a16151a87ee6b1db8322` adds SSH
collection at definitive parser limits after the retained CI implementation. Its
local checks passed without supplied Cargo profile overrides:

- `cargo fmt --all -- --check`.
- `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings`.
- `cargo test --locked --workspace --all-features`.
- `python3 -m unittest discover -s scripts -p 'test_*.py'` (59 tests).
- `python3 scripts/check-architecture.py`.
- `python3 scripts/test-service-identification.py --require-clean --report target/service-identification/report.json` (five profiles, 360 cases).

The retained CI run also checked the detached offline consumer and
warnings-denied documentation with private items in portable, native Layer3 and
all-feature profiles. V12 release asset staging, binary-generated documentation,
BUILD-METADATA identity and `scripts/verify-archive.py` checks used an all-feature
debug binary; this is a disclosed smoke variant rather than a release build.
The two released clock/scope stats examples retain their v10 markers while the
packaged producer emits v12. The SSH parser-limit boundary is covered by the
subsequent source's core/workflow regressions; it is not an additional fixture
condition in the retained 18-scenario reports.

These results close M8's applicable ground-truth and ordinary-socket gates.
Broader raw/native inventories and M2/M3/M5/M7 acceptance remain open.
Reports retain work, elapsed time and actual application byte counts; M8 adds
no retained-state or peak-RSS benchmark measurement. Held-out coverage and
confidence evaluation remain M9 work. Versions remain untrusted claims.
