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

## Runtime status

The runner contains 29 training/acceptance fixtures and 21 held-out fixtures:
50 scenarios, 200 case-runs per profile, and 1,000 case-runs for five profiles on
one platform. CI executes this inventory on Linux x86_64, macOS ARM64,
macOS Intel, and Windows x64 and preserves the complete report even on failure.

| Platform | Runtime evidence | Status |
| --- | --- | --- |
| Linux x86_64 | Local acceptance is being recorded for this implementation. | Pending |
| macOS ARM64 | CI route configured; no M9 runtime report recorded here. | Unavailable in the local environment |
| macOS Intel | CI route configured; no M9 runtime report recorded here. | Unavailable in the local environment |
| Windows x64 | CI route configured; no M9 runtime report recorded here. | Unavailable in the local environment |

Compilation and configured CI jobs do not close the macOS/Windows runtime gate.
The M8 reports retain their historical cleartext revision and do not establish
M9 TLS runtime acceptance.

## Validation

`python3 -m unittest scripts/test_service_identification.py` passes 17 contracts,
including immutable holdout enforcement, independent TLS fixture certificate
and SNI behavior, retained unexpected outcomes, uncertainty shares, separate
confidence counts, source-backed hostname/CPE metadata, and failure paths in
the existing acceptance runner.

Run the complete bounded inventory with:

```sh
python3 scripts/test-service-identification.py --require-clean \
  --report target/service-identification/report.json
```

Reports identify the exact revision, worktree cleanliness, operating system,
architecture, Python/OpenSSL fixture runtime, corpus digest, held-out digest,
build flags, and every attempted command. A dirty-worktree report is useful
development evidence but does not establish acceptance of a clean revision.
