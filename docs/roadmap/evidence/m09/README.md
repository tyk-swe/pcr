# M9 TLS and held-out identification evidence

[Runner](../../../../scripts/test-service-identification.py) builds five profiles
for dual-stack JSON/NDJSON cleartext and TLS fixtures: 29 training + 21 held-out
scenarios = 200 cases/profile, 1,000/platform, 4,000 closing case-runs using the
[fixed loopback TLS fixture](../../../../scripts/fixtures/service-identification/README.md).

## Fixed training and held-out split

[Holdout 1.0.0](held-out.v1.json) (`97267ae4`, SHA-256
`399ae8d919fe3ca2ac32c62962eee37e54a811c5dee30b02f9226e45be94774c`) was frozen
before rule authorship and is separate from
[training bytes](../../../../crates/packetcraftr/data/service-probes.training.v1.json).
Of 21 declared instances, 18 eligible services form the coverage denominator
(12 matched / 66.67%, 4 unknown / 22.22%, 2 ambiguous / 11.11%), while 3
malformed/TLS-failure/deadline fixtures test failure outcomes.

| Observed outcome | Per profile | Per platform (five profiles) |
| --- | ---: | ---: |
| Matched | 48 | 240 |
| Unknown | 16 | 80 |
| Ambiguous | 8 | 40 |
| Malformed | 4 | 20 |
| TLS handshake failed | 4 | 20 |
| Deadline budget exhausted | 4 | 20 |
| Total held-out case-runs | 84 | 420 |

## Runtime status

| Platform | Runtime evidence | Status |
| --- | --- | --- |
| Linux x86_64 | [ci-5e5a4147/linux.json.gz](ci-5e5a4147/linux.json.gz) (5 profiles, 1,000 case-runs) | Passed |
| macOS ARM64 | [ci-5e5a4147/macos-arm64.json.gz](ci-5e5a4147/macos-arm64.json.gz) (5 profiles, 1,000 case-runs) | Passed |
| macOS Intel | [ci-5e5a4147/macos-x86_64.json.gz](ci-5e5a4147/macos-x86_64.json.gz) (5 profiles, 1,000 case-runs) | Passed |
| Windows x64 | [ci-5e5a4147/windows.json.gz](ci-5e5a4147/windows.json.gz) (5 profiles, 1,000 case-runs) | Passed |

[Closing CI 38127739273](https://github.com/tyk-swe/pcr/actions/runs/38127739273)
passed at clean `5e5a41470c0c63404ca3e581067fded136eda1ce` (2026-10-11); see
[manifest](ci-5e5a4147/manifest.json), [job conclusions](ci-5e5a4147/ci-jobs.json),
[Linux isolated report](ci-5e5a4147/native-isolated.json), and the earlier
incomplete `9289960d` [local](local-9289960d/manifest.json) /
[CI](ci-9289960d/manifest.json) records. See also the
[TLS](../../../../examples/documents/output-identify-tls-success.json) and
[SMTP](../../../../examples/documents/output-identify-success.json) examples.

```sh
python3 scripts/test-service-identification.py --require-clean \
  --report target/service-identification/report.json
```
