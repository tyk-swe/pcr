# M9 TLS and held-out identification evidence

The [acceptance runner](../../../../scripts/test-service-identification.py)
exercises cleartext and TLS application identification with ordinary bounded
IPv4/IPv6 loopback sockets. Every supported feature profile runs the same
fixtures separately: portable, default, native Layer2, pcap-free native Layer3,
and all features. Each fixture publishes JSON and NDJSON results. A failed build,
unavailable address family, unexpected outcome, or fixture fault fails the
profile and remains in its report.

The fixture server uses Python's standard-library `ssl`; it does not share the
client's TLS implementation. Its [original certificate and public test key](../../../../scripts/fixtures/service-identification/README.md)
are checked in once, so runtime acceptance needs no OpenSSL command or external
service. TLS cases check exact decrypted request/response bytes, presented DER
certificate fidelity, numeric targets without SNI, explicitly declared SNI,
negotiated version/cipher observations, and separate encrypted and application
byte accounting. Refused and silent handshakes, encrypted read caps, and
certificate retention caps have explicit outcomes. A certificate never
authenticates a host, name, product, or version.

## Fixed training and held-out split

The [held-out manifest](held-out.v1.json), version 1.0.0, was fixed in commit
`97267ae4` before the M9 SMTP/FTP match rules were authored. Its SHA-256 is
`399ae8d919fe3ca2ac32c62962eee37e54a811c5dee30b02f9226e45be94774c`.
The acceptance owner independently authored 21 service instances and supplied
only their count and digest to the corpus owner. Those response bytes were not
used to write or tune rules. The runner rejects a changed manifest rather than
silently replacing the holdout after evaluation.

Training SMTP/FTP instances and their exact bytes are declared in the
[training manifest](../../../../crates/packetcraftr/data/service-probes.training.v1.json)
and shipped corpus provenance. The held-out split is by service instance, with independently
chosen versions, hostnames, status lines, and response bytes. Both sets are
project-authored fixtures under AGPL-3.0-only; no scanner database or third-party
fingerprint corpus was copied. To select one reviewed probe per fixture, the
runner projects the shipped document to that probe and its unchanged match
rules. Reports retain the shipped corpus identity, version, and document digest.

The 21 held-out instances cover SSH, HTTP/HTTPS, DNS, SMTP, and FTP, unfamiliar
products and banners, conflicting products and versions, a misleading software
claim, malformed bytes, and two TLS handshake failure paths. Eighteen valid
service instances form the coverage denominator; malformed input and refused
or timed-out TLS handshakes remain separate observed outcome classes. They are
not successful skips.

## Quality reporting

Each feature-profile report publishes observed matched coverage, unknown share,
ambiguous share, every outcome count, and confidence-category counts. `claim`
and `protocol` are reported separately. Presented-token fidelity measures
whether an unambiguous claim reproduces the fixture's untrusted product/version
tokens. The misleading fixture deliberately disagrees with its independent
implementation identity; its plausible banner must still have `claim`
confidence. No software identity accuracy or calibrated probability is inferred.

IPv4/IPv6 and JSON/NDJSON repetitions are case-runs of the same declared
instances, not additional independent services. These fixtures measure the
declared corpus under controlled responses; they establish no production
prevalence, broad Internet coverage, performance baseline, or operating-system
identification result. Passive TLS decoding and JA3/JA4 are outside this active
identification report.

The clean Linux run records the same held-out outcome distribution in every
profile. Its 21 independent instances produce 84 case-runs per profile because
each instance is exercised through both address families and output formats.

| Observed outcome | Per profile | Five profiles |
| --- | ---: | ---: |
| Matched | 48 | 240 |
| Unknown | 16 | 80 |
| Ambiguous | 8 | 40 |
| Malformed | 4 | 20 |
| TLS handshake failed | 4 | 20 |
| Deadline budget exhausted | 4 | 20 |
| Total held-out case-runs | 84 | 420 |

The eligible denominator is 72 case-runs per profile, or 360 across five
profiles: coverage is 66.67%, unknown share is 22.22%, and ambiguous share is
11.11%. Equivalently, the 18 eligible independent instances comprise 12 matched,
four unknown, and two ambiguous instances. The three failure fixtures remain
outside this denominator and have their actual outcomes recorded above.

Across five profiles, candidates retain 300 `claim` confidence labels and 20
`protocol` labels. Unambiguous presented-token fidelity accounts for 220 claim
results and 20 protocol results; ambiguous candidates are excluded from this
count. The single misleading fixture appears in 20 case-runs and remains a
claim in every run. These counts verify declared fixture behavior without
asserting software identity accuracy.

## Runtime status

The runner contains 29 training/acceptance fixtures and 21 held-out fixtures:
50 scenarios, 200 case-runs per profile, and 1,000 case-runs for five profiles on
one platform. CI executes this inventory on Linux x86_64, macOS ARM64,
macOS Intel, and Windows x64 and preserves the complete report even on failure.

| Platform | Runtime evidence | Status |
| --- | --- | --- |
| Linux x86_64 | [Lossless local report](local-9289960d/linux-x86_64.json.gz): five profiles, 1,000 case-runs, zero failures. | Passed |
| macOS ARM64 | CI route configured; no M9 runtime report recorded here. | Pending CI report |
| macOS Intel | CI route configured; no M9 runtime report recorded here. | Pending CI report |
| Windows x64 | CI route configured; no M9 runtime report recorded here. | Pending CI report |

The local report records clean implementation revision
`9289960d21738edce6d48f5c808a3405fe83597b`, Linux x86_64, Python 3.14.4,
and OpenSSL 3.5.5. Its [integrity manifest](local-9289960d/manifest.json)
retains the corpus and held-out digests, compressed and uncompressed report
SHA-256 values, and exact profile/case totals. The original report decompresses
byte-for-byte to the runner output.

Compilation and configured CI jobs do not close the macOS/Windows runtime gate.
The M8 reports retain their historical cleartext revision and do not establish
M9 TLS runtime acceptance.

## Validation

`python3 -m unittest scripts/test_service_identification.py` passes 17 contracts,
including immutable holdout enforcement, independent TLS fixture certificate
and SNI behavior, retained unexpected outcomes, uncertainty shares, separate
confidence counts, source-backed hostname/CPE metadata, and failure paths in
the existing acceptance runner.

The [TLS identification example](../../../../examples/documents/output-identify-tls-success.json)
was captured from a successful original loopback fixture with a declared SNI
name and validated against the output/v13 schema. It retains the presented
certificate DER, negotiated TLS parameters, encrypted/application counters,
and unauthenticated nginx claim with its reviewed CPE source.

Run the complete bounded inventory with:

```sh
python3 scripts/test-service-identification.py --require-clean \
  --report target/service-identification/report.json
```

Reports identify the exact revision, worktree cleanliness, operating system,
architecture, Python/OpenSSL fixture runtime, corpus digest, held-out digest,
build flags, and every attempted command. A dirty-worktree report is useful
development evidence but does not establish acceptance of a clean revision.
