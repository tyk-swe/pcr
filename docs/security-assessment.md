# Local security investigations and assessments

These workflows report observed evidence and suspicious patterns. Findings do not
assert exploitability or compromise. They never download threat feeds, expand
numeric targets, follow redirects, crawl applications, or test credentials.

```sh
packetcraftr --output json analyze hunt capture.pcapng --indicators indicators.json > hunt.json
packetcraftr --output json analyze dns-anomalies capture.pcapng > dns.json
packetcraftr --output json analyze beacons capture.pcapng > beacons.json
packetcraftr --output json network audit-tls 192.0.2.10:443 --server-name example.test > tls.json
packetcraftr --output json network audit-http 192.0.2.10:443 --tls --server-name example.test --host example.test --path / > http.json
packetcraftr --output json analyze scan-diff before.json after.json > changes.json
packetcraftr --output json analyze report hunt.json dns.json beacons.json tls.json http.json changes.json --html assessment.html
```

The six investigation commands support text, JSON, and NDJSON (`finding` events
followed by `complete`). Report generation supports text and JSON. Findings use
stable rule IDs, severity (`info`, `low`, `medium`, `high`, `critical`), measured
evidence, source frame references, and completeness flags. Successful execution
returns zero; `--fail-on medium` (or another severity) returns 1 when a finding
meets the threshold. Operational errors retain the ordinary CLI error contract.

## Capture investigations

The IOC document is local JSON with schema `packetcraftr.indicators/v1` and a
nonempty `indicators` list. Each entry has a unique `id`, `kind`, and `value`.
Kinds are `ip`, `cidr`, `domain`, `domain_suffix`, `ja3`, and `ja4`. See
[the example](../examples/documents/indicators.json) and
[the versioned schema](../schemas/packetcraftr.indicators.v1.schema.json).
Domain matching ignores ASCII case and a trailing dot. Suffix matching includes
the apex and requires a dot boundary: `example.test` matches
`a.example.test`, but not `badexample.test`. IPs are compared numerically.
Fingerprint matches are observations of client-controlled values, not identities.

Hunt reads visible IP endpoints, DNS names and address records, cleartext HTTP/1
Host headers on ports 80, 8000 and 8080, and reassembled TLS ClientHellos. It cannot
inspect encrypted DNS or HTTP. HTTP and DNS stream gaps, malformed messages,
truncation, and partial TLS sessions remain explicit.

DNS anomalies use epoch-aligned 60-second windows per capture scope and client.
`dns.nxdomain_ratio` requires at least 20 matched responses with an NXDOMAIN ratio
of at least 0.50. Unmatched and duplicate responses do not enter that denominator.
`dns.high_entropy_labels` requires 20 distinct leading query labels sharing a
suffix, each at least 32 characters with Shannon entropy at least 4 bits per
character. Use `--window-seconds`, `--min-responses`, `--nxdomain-ratio`,
`--min-labels`, `--min-label-length`, and `--min-entropy` to adjust thresholds.

Beacon detection groups SYN attempts by capture scope, source address,
destination address, and destination port. Retransmissions of the same SYN are
deduplicated. Defaults require six distinct attempts, mean intervals of at least
one second, and population interval coefficient of variation no greater than
0.10. Use `--min-attempts`, `--min-interval-seconds`, and `--max-cv` to adjust.
Clock regressions conservatively suppress timing conclusions for the capture,
including regressions on filtered-out frames. Missing capture traffic cannot be
reconstructed; an observed cadence can also be legitimate scheduled activity.

Capture commands accept the existing `--filter`, decode overrides, capture time
bounds, reassembly controls, and resource presets. `--max-findings`, `--max-groups`,
`--max-observations`, and `--max-result-bytes` bound security state and output;
application parsing uses the existing `--max-application-*` limits. Group evidence
includes up to 64 representative frame references, explicitly marked as sampled.
Resource exhaustion fails with the usual bounded-operation error rather than
silently producing a complete report.

## Live audits

Both audits require only TCP socket providers and ordinary user privileges.
They honor destination allowlists, public-destination opt-in, cancellation,
operation deadlines, write authorization, and bounded encrypted traffic.
`--timeout-ms` bounds the connection and complete exchange. TLS byte budgets use
`--max-tls-write-bytes` and `--max-tls-read-bytes`; HTTP headers also use
`--max-response-bytes` (at most 65535).

TLS auditing observes one negotiated protocol/cipher and SHA-256 fingerprints
of the presented DER certificate chain. Chain validity and hostname/IP matching
are checked independently in the TLS subsystem. Bundled WebPKI roots are used by
default. `--ca-file roots.pem` replaces them. `--server-name` sets the TLS identity
and SNI without resolving or changing the numeric endpoint. Without it, the
certificate must match the target IP. No revocation fetching, legacy-protocol
enumeration, or exhaustive cipher testing is performed.

HTTP auditing sends one HTTP/1.1 `HEAD /` with `Connection: close`. It checks an
enforced CSP, frame protection, `nosniff`, Referrer-Policy, HTTPS HSTS, and observed
cookie attributes. Missing headers produce low-severity configuration findings;
context determines which controls are appropriate. Cookie values are redacted.
No redirect is followed. For HTTPS, the request is withheld unless both chain and
name checks pass; that report identifies the missing HTTP evidence.

## Scan comparison and reports

Scan diff requires successful native aggregate JSON and matching raw/connect
methods (including raw TCP scan mode). It compares scoped numeric endpoints and
inferred states backed by supporting evidence. Missing endpoints are coverage
changes, never presumed closed. Inconclusive or unavailable measurements are
separate `scan.evidence_unavailable` findings.

Reports accept aggregate JSON from these six commands only. They embed severity
filters, source-file SHA-256 hashes, evidence, completeness notes, and remediation
without external assets. All captured text is HTML escaped. Publication uses the
existing staged writer and refuses existing files, including symlinks. The JSON
summary uses the additive `packetcraftr.output/v1` security report contract.
