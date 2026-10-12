# Service identification

`identify` / `Client::identify` is explicit; scans never start it automatically.
Ordinary numeric TCP/UDP sockets work in every profile without raw privileges.
`identify::Endpoint::from_scan` selects inferred TCP-open and UDP-open/open-or-filtered
endpoints for a separate invocation with independent authorization/budgets.

```sh
packetcraftr --output json identify 127.0.0.1:8080 '[::1]:2222'
packetcraftr --output ndjson identify 192.0.2.53:5353 --transport udp --allow-public-destinations
packetcraftr identify 127.0.0.1:8080 --corpus examples/documents/service-probes.json
```

Run live examples only on explicitly authorized lab endpoints. IPv6 link-local
endpoints need numeric scope IDs. There is no implicit lookup, authentication,
redirect, transfer, or mutable request. Reauthorize final endpoints and check
peer identity/exact request bytes before I/O. UDP-profile confirmation still only
means configured checks matched.

## Probes and intensity

Intensity 1–9 (default 2) selects reviewed probes on any permitted port; selection
is transport-aware, never inferred from port numbers. Each TCP attempt uses a
fresh connection, each UDP attempt one datagram, without UDP→TCP fallback.
The closed request language is SSH/SMTP/FTP greetings, HTTP HEAD, and nonrecursive
DNS questions including `version.bind` CH TXT. Arbitrary bytes/regexes are excluded.

Parsers retain exact bytes. Informational HTTP heads precede a final head whose
status/Server supplies fields; 101 is terminal. SMTP needs an explicit Postfix/Exim
version to match these corpus rules; a hidden version may stay unknown.
FTP uncoded multiline continuation remains available. Neither hostname nor port
alone establishes product. Description fields allow ≤512 Unicode characters/
2,048 UTF-8 bytes. Bounded documents and runtime checks validate IDs/references.

## TLS-wrapped services

`--tls` wraps TCP probes with TLS 1.2/1.3 (rustls 0.23.45/ring 0.17.14), without
system TLS. Numeric defaults send no SNI; `--server-name` declares SNI without
resolution. Peer certificate trust/hostname authentication is intentionally absent;
handshake signatures remain verified. No STARTTLS, UDP TLS, or cleartext fallback.

```sh
packetcraftr --output json identify 127.0.0.1:8443 --tls --server-name lab.example
```

Presented ordered DER chains, negotiated protocol/cipher, handshake status, and
SNI remain unauthenticated evidence. Application writes count accepted plaintext,
even if later flush fails; encrypted counters describe completed socket transfers.
Failed TLS retains evidence and prevents further application writes.

| TLS bound | Default |
| --- | --- |
| Encrypted bytes read / written per connection | 131,072 each |
| I/O steps per connection | 64 |
| Handshake deadline within connection lifetime | 1 s |
| Retained certificates / DER bytes per connection | 8 / 65,536 |
| Operation encrypted bytes per direction / certificate bytes | 8 MiB / 1 MiB |
| Host encrypted bytes per direction / certificate bytes | 1 MiB / 128 KiB |

Smaller enclosing budgets narrow before I/O; failed handshakes are charged.
Certificate truncation omits whole certificates. Controls are
`--tls-max-wire-write-bytes`, `--tls-max-wire-read-bytes`, `--tls-max-steps`,
`--tls-handshake-timeout-ms`, `--tls-max-certificates`, `--tls-max-certificate-bytes`,
`--tls-operation-max-wire-bytes`, `--tls-host-max-wire-bytes`,
`--tls-operation-max-certificate-bytes`, and `--tls-host-max-certificate-bytes`.
See help for validated ranges. Fixed [public test fixtures](../scripts/fixtures/service-identification/README.md)
are not secrets or trust anchors and are not regenerated during acceptance.

## Budgets and sensitive endpoints

Operation/host/connection/probe scopes charge actual partial application transfers;
retries spend attempts and fresh connections. Host identity includes link-local
interface, coalesces mapped IPv4/irrelevant global IPv6 scope, and ignores irrelevant
flow metadata. Live DNS IDs use fresh entropy before I/O and do not repeat in one
bounded operation; corpus id_base/offline IDs do not choose live identities.

Smaller receive allowances narrow reads. Full TCP buffers mean truncated unless
a protocol record is complete; oversized UDP retains a prefix. The operation
also caps retained candidates (evidence and summaries) at 8,192; exhaustion keeps
bytes and marks the report incomplete.

| Scope bound | Valid range |
| --- | --- |
| Distinct endpoints | At most 1,024 |
| Attempts in each scope | 1–4,096 |
| Written bytes | 0–64 MiB; zero permits speak-first only |
| Retained response bytes | 1 byte–64 MiB; connection/probe additionally≤65,535 |
| Timeout | Positive, at most one hour |

Use `--max-attempts`, `--max-write-bytes`, `--max-read-bytes`,
`--operation-timeout-ms` and corresponding host/connection/probe controls.
Overall `--max-duration-ms` also includes preparation/publication; allow headroom
for a partial report. Overall expiry/cancellation may yield a typed terminal error;
an unwritable stream cannot promise a terminal.

[Exclusions](../crates/packetcraftr/data/service-exclusions.json) apply before
probe planning: excluded records send nothing/spend no attempts. `--exclusions`
loads operator data; `--ignore-exclusions` overrides only that set, never policy
or budgets. Reports retain version/reasons. Limits: 64 entries, each 1–2,048 unique
nonzero ports, 64 KiB serialized bytes; overlaps preserve all reasons/provenance.

## Reading evidence

[v14](../schemas/packetcraftr.output.v14.schema.json) separates exact planned
request/response hex, actual partial bytes written, numeric peers, observed claims,
candidates, ordinal confidence, and corpus/probe/rule/field provenance.
`claim` and `protocol` are not probabilities or authentication.
Excluded/unknown/ambiguous/malformed/truncated/budget_exhausted/tls_failed are
explicit. Nonmatching outcomes have empty candidates; ambiguous versions are
erased, including conflicts across individually singular probes. Earlier matches
can survive later budget exhaustion. No result is a vulnerability finding.

JSON retains endpoint records; NDJSON emits identify_endpoint plus terminal usage,
data versions, elapsed time, complete/cancelled state. Pre-I/O admission conservatively
bounds hex/claims/candidate copies within the 16 MiB record ceiling.
Read complete/error, not just endpoint records. See [consumer rules](consumer-compatibility.md).

## Corpus quality and supported metadata

Bundled original corpus 1.1.0 includes SMTP/FTP and supported observed hostnames/
static wildcard-version CPEs with observed_field/match_rule sources; no device
types are bundled. [Data policy](scanner-data-policy.md) governs maintenance.

[M9 evidence](roadmap/evidence/m09/README.md) records 21 fixed held-out instances,
18 eligible: 66.67% matched, 22.22% unknown, 11.11% ambiguous. Malformed and TLS
failure fixtures retain separate outcomes. Families/formats/profiles repeat the
same instances, not independent services. Token fidelity is not implementation
identity, calibrated confidence, production prevalence, or a performance baseline.
