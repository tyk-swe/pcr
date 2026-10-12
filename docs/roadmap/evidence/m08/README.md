# M8 service identification evidence

Historical ordinary TCP/connected UDP acceptance: no raw capture/routes/neighbors/
injection. Applicable seams are peer identity, timeouts/cancellation, and bounded
response retention (including Winsock WSAEMSGSIZE prefix). Independent inventory
[dataset 1.4.0](../../../scanner-corpus.v1.json) and
[runner](../../../../scripts/test-service-identification.py) distinguish executed
conditions from compilation/unavailable paths.

## Reviewed runtime evidence

Corrected inventory supersedes initial `928ad8d555fe8b34abd144083612b54ace0fef1f`
reports. Clean `99a9cf23216eb490892c0b6659e303d1a0b02c3d` passed 2026-10-10 in
[CI 38009601998](https://github.com/tyk-swe/pcr/actions/runs/38009601998), all seven
applicable jobs; privileged Linux launcher is skipped on PRs. The reports name
PR merge checkout `103a1594fd8d94262404bd73b5aee94494877690`, with identical
implementation tree. [Manifest](manifest.json) retains head/base/checkout/tree
identities, original/gzip hashes, sizes, source artifacts, and counts.

| Platform | Corrected acceptance report | Profiles | Passed cases | Failed / unavailable |
| --- | --- | ---: | ---: | ---: |
| Linux x86_64 | [linux.json.gz](linux.json.gz) | 5 | 360 | 0 / 0 |
| macOS ARM64 | [macos-arm64.json.gz](macos-arm64.json.gz) | 5 | 360 | 0 / 0 |
| macOS Intel | [macos-x86_64.json.gz](macos-x86_64.json.gz) | 5 | 360 | 0 / 0 |
| Windows x64 | [windows.json.gz](windows.json.gz) | 5 | 360 | 0 / 0 |

Four platforms × five profiles × 18 fixtures × two families × two formats =
1,440 case-runs across 20 profile executions, no failure/unavailable path. Fixtures cover
SSH/HTTP/DNS, unfamiliar/conflicting/deceptive claims, malformed/truncated replies,
byte/deadline/exclusion/intensity bounds. These are repeated conditions, not 1,440
independent services. Zero-timestamp gzip is lossless: `gzip -dc linux.json.gz`.

[Independent audit](independent-audit.json) checks all cases' revision/flags,
numeric endpoints, exact bytes, outcomes/uncertainty/confidence/provenance/budgets/
timing against explicit inventory. Reports retain result payloads; raw envelope/
schema/framing checks remain in runner and CLI conformance tests.

## Local validation

Later `70a9c66eded90db44930a16151a87ee6b1db8322` added definitive SSH parser-limit
collection. Historical local fmt/all-feature Clippy/tests, 59 Python tests,
architecture, and five-profile 360-case runner passed without profile overrides.
The boundary is owner regression coverage, not an extra retained fixture condition.

Retained CI also checked detached public consumer and warning-denied private
rustdocs in portable/Layer 3/full profiles. Historical v12 archive staging/generated
docs/metadata/verification used a full-feature debug binary: smoke, not release
build. Published clock/scope examples kept v10 markers; never relabel these artifacts.

## Limits

Closes M8's applicable independent/socket gates, not broader M2/M3/M5/M7 raw/native
acceptance. Work/time/application bytes are retained, not peak-RSS/retained-state
benchmarks. [M9 evidence](../m09/README.md) subsequently added TLS and a fixed
holdout; it does not rewrite these cleartext reports. All versions remain claims.
