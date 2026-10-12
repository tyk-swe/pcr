# M9 TLS and held-out identification evidence

[Runner](../../../../scripts/test-service-identification.py) builds five profiles
for original dual-stack JSON/NDJSON cleartext/TLS fixtures: 29 training + 21 held-out
scenarios = 200 cases/profile, 1,000/platform, 4,000 closing cases. No remote peer,
external DNS, raw privilege, mutable request, or system TLS client is used.
Python ssl serves the [fixed public test certificate/key](../../../../scripts/fixtures/service-identification/README.md);
it is unauthenticated observation, not trust. Missing prerequisites/families fail.
Reports are historical revision-bound evidence, not a run of current main.

## Fixed training and held-out split

[Holdout 1.0.0](held-out.v1.json) was fixed in `97267ae4` before rule authorship:
SHA-256 `399ae8d919fe3ca2ac32c62962eee37e54a811c5dee30b02f9226e45be94774c`.
Independent owner supplied count/digest only; response bytes were not used for
writing/tuning rules. Runner rejects changes rather than replacing after evaluation.
[Training bytes](../../../../crates/packetcraftr/data/service-probes.training.v1.json)
and corpus provenance remain separate. All are project-authored AGPL fixtures;
no third-party scanner database. Runner projects one unchanged reviewed probe/rules
per fixture, retaining shipped corpus/version/document digest.

21 independently declared instances span SSH, HTTP/HTTPS, DNS, SMTP/FTP, unfamiliar/
conflicting/misleading claims, malformed input, and TLS failure. 18 eligible valid
services form coverage denominator; three failure conditions are real outcomes,
not successful skips. Family/format/profile repeats add no independent services.

## Quality reporting

| Observed outcome | Per profile | Per platform (five profiles) |
| --- | ---: | ---: |
| Matched | 48 | 240 |
| Unknown | 16 | 80 |
| Ambiguous | 8 | 40 |
| Malformed | 4 | 20 |
| TLS handshake failed | 4 | 20 |
| Deadline budget exhausted | 4 | 20 |
| Total held-out case-runs | 84 | 420 |

Every closing profile has this distribution. 18 eligible instances: 12 matched
(66.67%), 4 unknown (22.22%), 2 ambiguous (11.11%). Equivalent denominators are 72
eligible case-runs/profile and 360/platform; failures stay separate.

Claim/protocol confidence is ordinal. Presented-token fidelity checks untrusted
fixture tokens, never software identity. The misleading plausible banner remains
claim confidence despite independently different implementation identity.
Per platform: 300 claim/20 protocol candidate labels; 220 claim/20 protocol
unambiguous token-fidelity results; 20 misleading case-runs. Ambiguous candidates
are excluded from fidelity. Four-platform heldout totals: 1,680 runs, 1,440 eligible
(960 matched/320 unknown/160 ambiguous), 240 failures; 1,200 claim/80 protocol labels;
880 claim/80 protocol fidelity results; 80 misleading cases. Same 21 instances.
No calibrated probability, production prevalence, broad coverage, OS result,
passive JA3/JA4 finding, or performance baseline is inferred.

## Runtime status

| Platform | Runtime evidence | Status |
| --- | --- | --- |
| Linux x86_64 | [Lossless CI report](ci-5e5a4147/linux.json.gz): five profiles, 1,000 case-runs, zero failures. | Passed |
| macOS ARM64 | [Lossless CI report](ci-5e5a4147/macos-arm64.json.gz): five profiles, 1,000 case-runs, zero failures. | Passed |
| macOS Intel | [Lossless CI report](ci-5e5a4147/macos-x86_64.json.gz): five profiles, 1,000 case-runs, zero failures. | Passed |
| Windows x64 | [Lossless CI report](ci-5e5a4147/windows.json.gz): five profiles, 1,000 case-runs, zero failures. | Passed |

[Closing CI 38127739273](https://github.com/tyk-swe/pcr/actions/runs/38127739273)
passed eight jobs at clean `5e5a41470c0c63404ca3e581067fded136eda1ce` on 2026-10-11.
[Integrity manifest](ci-5e5a4147/manifest.json) retains 20 profiles/4,000 cases,
original/compressed digests, artifacts, corpus/holdout identity, recomputed quality.
Zero service failure/absence/unavailability.
[Job conclusions](ci-5e5a4147/ci-jobs.json) retain isolation/oracle/fuzz checks;
[native report](ci-5e5a4147/native-isolated.json) exercises all eight Linux scenarios.
Broader privileged macOS/Windows labs remain M3 work.

[Local report](local-9289960d/linux-x86_64.json.gz)/[manifest](local-9289960d/manifest.json)
bind `9289960d21738edce6d48f5c808a3405fe83597b`, Linux x86_64,
Python 3.14.4/OpenSSL 3.5.5, original bytes/digests/case totals.
[Earlier CI](ci-9289960d/manifest.json) remains incomplete: Linux/ARM accepted,
Windows no cases from CRLF-transformed manifest, Intel cancelled. LF attributes
fixed checkout bytes, not holdout/rules. Only closing four-platform run closes M9;
M8 cleartext reports retain their own revision.

## Validation

At closing revision: 17 runner contracts, workspace all-feature tests, five-profile
Clippy, rustdocs, architecture, 65 Python tests, dependency policy/fuzz advisories,
12 schema tests, and independent v13 validation of 6,000 retained payloads passed.
Schema inventory: 2,000 JSON aggregates/2,000 endpoints/2,000 stream summaries.
[TLS example](../../../../examples/documents/output-identify-tls-success.json)
retains SNI, DER, negotiated parameters, separate counters, untrusted nginx/CPE;
[SMTP example](../../../../examples/documents/output-identify-success.json) retains
training hostname provenance. Generated docs/release staging/archive checks passed.
Default-corpus TLS smoke completed 4.75 s/five TCP probes; one functional run is not
a speed baseline.

To reproduce complete bounded inventory on a clean reviewed checkout:

```sh
python3 scripts/test-service-identification.py --require-clean \
  --report target/service-identification/report.json
```

Reports retain revision/cleanliness/platform/architecture/fixture runtime,
corpus/holdout digests, flags, and every command. Dirty development reports never
establish clean-revision acceptance. Do not regenerate fixed fixture assets.
