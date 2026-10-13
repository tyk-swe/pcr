# M8 service identification evidence

Historical ordinary TCP/connected UDP acceptance using
[dataset 1.4.0](../../../scanner-corpus.v1.json) and
[runner](../../../../scripts/test-service-identification.py).

## Reviewed runtime evidence

Clean revision `99a9cf23216eb490892c0b6659e303d1a0b02c3d` passed 2026-10-10 in
[CI 38009601998](https://github.com/tyk-swe/pcr/actions/runs/38009601998)
(PR merge checkout `103a1594fd8d94262404bd73b5aee94494877690`, identical tree;
superseding `928ad8d555fe8b34abd144083612b54ace0fef1f`). [Manifest](manifest.json)
and [independent audit](independent-audit.json) retain digests, artifacts, and
per-case verification.

| Platform | Report | Profiles | Passed cases | Failed / unavailable |
| --- | --- | ---: | ---: | ---: |
| Linux x86_64 | [linux.json.gz](linux.json.gz) | 5 | 360 | 0 / 0 |
| macOS ARM64 | [macos-arm64.json.gz](macos-arm64.json.gz) | 5 | 360 | 0 / 0 |
| macOS Intel | [macos-x86_64.json.gz](macos-x86_64.json.gz) | 5 | 360 | 0 / 0 |
| Windows x64 | [windows.json.gz](windows.json.gz) | 5 | 360 | 0 / 0 |

4 platforms × 5 profiles × 18 fixtures × 2 IP families × 2 formats = 1,440
case-runs across 20 profile executions (SSH/HTTP/DNS, unknown/ambiguous/deceptive
claims, malformed/truncated replies, byte/deadline/exclusion/intensity bounds).
Later `70a9c66eded90db44930a16151a87ee6b1db8322` added SSH parser-limit regression
coverage. [M9 evidence](../m09/README.md) subsequently added TLS and a fixed
holdout.
