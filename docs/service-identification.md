# Service identification

`identify` interrogates explicitly selected numeric endpoints with bounded,
reviewed requests. It works over ordinary TCP and UDP sockets in every build
profile and does not require raw capture privileges. A scan never invokes it
implicitly. The library's `identify::Endpoint::from_scan` selects TCP endpoints
inferred open and UDP endpoints inferred open or open-or-filtered; callers then
invoke `Client::identify` explicitly.

```console
packetcraftr --output json identify 127.0.0.1:8080 --transport tcp
packetcraftr --output ndjson identify '[::1]:2222' --intensity 1
packetcraftr identify 192.0.2.53:5353 --transport udp --intensity 3
packetcraftr identify 192.0.2.10:8080 --corpus examples/documents/service-probes.json
```

Endpoint arguments are numeric socket addresses, including a numeric scope ID
for link-local IPv6. Identification performs no name lookup, TLS negotiation,
authentication, redirect following, DNS transfer, or mutable application request.
Every connection and datagram reauthorizes its final numeric destination. The
actual peer and the exact outgoing application bytes are checked before sending.
Ordinary scan UDP profile confirmation retains its existing meaning: a response
satisfied that profile; it does not identify a product.

## Probes and intensity

The bundled, independently versioned
[probe corpus](../crates/packetcraftr/data/service-probes.json) includes:

| Intensity | Probe | Request and interpretation |
| --- | --- | --- |
| 1 | SSH, TCP | Receives the server's identification line without transmitting SSH bytes. |
| 2 | HTTP, TCP | Sends `HEAD / HTTP/1.0` and parses a bounded response head and `Server` fields. |
| 2 | DNS, TCP and UDP | Sends a nonrecursive root IN A query; validates framing, transaction ID and echoed question. |
| 3 | DNS version metadata, TCP and UDP | Sends a nonrecursive `version.bind` CH TXT query; interprets returned text as a claim. |

`--intensity` is a threshold from 1 through 9, default 2. All selected probes run
on any allowed port of their transport. A conventional port number is neither a
probe selector nor evidence of a service. Each attempt uses one fresh TCP
connection or one datagram. There is no automatic UDP-to-TCP fallback.

HTTP collection retains informational heads and waits for the final response;
101 Switching Protocols is terminal. Status and Server claims come only from
the final head, while preceding heads remain in the exact response evidence.

The versioned [probe document schema](../schemas/packetcraftr.service-probes.v1.schema.json)
accepts a closed request language: banner collection, HTTP HEAD, and the two
nonrecursive DNS queries above. Operator documents cannot introduce arbitrary
request bytes or methods. Matching uses anchored ASCII literals over parsed
fields and bounded version-token extraction; no unbounded regular expressions
are accepted. Each probe includes a read-only review and maintenance/source
metadata, and each match rule has its own provenance. Core owns document
validation, response parsing and deterministic matching independently of I/O.
Shared descriptive text is limited to 512 Unicode characters and 2,048 UTF-8
bytes per value, in addition to each document's enclosing byte-size limit.
The schema rejects repeated objects; the runtime also checks unique IDs and
probe/rule references, which require validation across document entries.

## Budgets and sensitive endpoints

Identification has attempt, application write-byte, retained response-byte and
time limits at operation, host, connection and probe scopes. All four scopes
must admit an attempt before I/O; partial transfers are charged with their actual
completed byte counts. Host limits span all ports and transports of the same
numeric host, including the interface scope of link-local IPv6 addresses.
Mapped IPv4 and irrelevant global IPv6 scope IDs share the same host budget.
Endpoint uniqueness uses that same host identity plus port and transport;
irrelevant IPv6 flow information does not make a second endpoint distinct.
Policy traffic declarations follow applicable, writable probes and their finite
attempt bounds: banner collection declares only a TCP connection, while a UDP
query declares only a message. Final destination and exact request-byte checks
still precede every transmission.
Live DNS transaction IDs use a fresh system-random seed for each operation and
do not repeat across its bounded probes or retries. Corpus `id_base` values do
not choose live identities; the core request builder accepts an explicit ID for
offline reconstruction. Entropy is acquired before probe I/O and failures retain
their original source.
Retries consume attempts and
fresh connection resources. A smaller enclosing allowance reduces the receive
buffer rather than allowing an oversize read. A full receive buffer is
conservatively reported as truncated, unless the TCP protocol record is already
complete. UDP reads retain only the permitted prefix of an oversized datagram.
An additional operation-wide hard limit of 8,192 retained candidates, including
evidence and endpoint summaries, bounds match-result amplification. Reaching it
retains the response bytes and stops further probes with an incomplete report.

Use `--max-attempts`, `--max-write-bytes`, `--max-read-bytes`,
`--operation-timeout-ms`, and the corresponding `--host-*`, `--connection-*`
and `--probe-*` controls. `--max-duration-ms` bounds the entire CLI invocation,
including preparation and publication; its default leaves time to publish a
partial report after the operation budget expires. Expiry of the overall
invocation deadline or cancellation may terminate publication with the ordinary
typed CLI error contract. `identify --help` lists defaults. Requests accept at
most 1,024 distinct endpoints; each scope allows 1–4,096 attempts, at most
64 MiB of write bytes and 1 byte–64 MiB of retained response bytes, and a
positive timeout no greater than one hour. Connection and probe response limits
are additionally capped at 65,535 bytes. A zero write allowance permits
speak-first collection while preventing active probes.

The independently versioned
[sensitive-service exclusion document](../crates/packetcraftr/data/service-exclusions.json)
excludes raw printer queues and selected industrial-control and management
endpoints before probe selection or request construction. Excluded records send
nothing and consume no attempts. `--exclusions PATH` supplies an operator
[exclusion document](../examples/documents/service-exclusions.json).
`--ignore-exclusions` explicitly disables this exclusion set for one operation;
destination authorization and all resource budgets still apply. The exclusion
set and version are included in the report.
Exclusions accept at most 64 entries, each with 1–2,048 unique nonzero ports.
Entries form a union: overlapping ports retain their separate reasons and
provenance. Serialized exclusion documents remain bounded to 64 KiB, and these
entry/port limits also bound directly constructed documents.

## Reading evidence

JSON and NDJSON use the current
[output contract](../schemas/packetcraftr.output.v12.schema.json). Each endpoint
record separates exact probe/response bytes, observed fields, candidate matches,
ordinal confidence and match provenance. Request evidence records the planned
bytes and the actual `bytes_written`, including partial writes. Response bytes
and field values remain faithful to their octets; malformed and incomplete
responses retain their evidence. Source errors remain available to library
callers and as diagnostics in CLI output.

NDJSON emits one bounded envelope per endpoint. Before probing, the CLI checks
a conservative size bound from selected probes, available attempt/read budgets,
hex evidence, claims and both candidate copies against the 16 MiB record ceiling.
Configurations that could exceed it fail before network I/O. Reduce the host,
operation or probe limits, or use aggregate JSON for larger bounded evidence.

`claim` confidence means an unauthenticated software field matched a corpus
literal. `protocol` means protocol syntax supports the candidate's protocol
classification. These are ordinal categories, not measured probabilities. An
advertised `nginx/99.0` value may be deliberate deception; its candidate is still
only a claim. Even an exact matched version does not authenticate an endpoint
or make a vulnerability finding.

Unknown products, incompatible product or version claims, malformed responses,
and truncated observations have explicit outcomes. Unknown and ambiguous
outcomes expose no exact matched versions. Raw advertised strings remain in
observed evidence so consumers can inspect the cause of uncertainty. The same
corpus version and response evidence reproduce the same core match result.
Output/v12 enforces empty candidates for nonmatching outcomes and erased versions
for ambiguous results, including probe evidence. An endpoint's ambiguity can
come from different probes, each retaining only one conflicting candidate.
Budget exhaustion can retain earlier matches and their exact evidence.

The [scanner data policy](scanner-data-policy.md) and the bundled
[probe](../crates/packetcraftr/data/service-probes.provenance.yaml) and
[exclusion](../crates/packetcraftr/data/service-exclusions.provenance.yaml)
manifests describe authorship, redistribution rationale, maintenance and fixture
coverage. The corpus is deliberately small; it does not claim Nmap-equivalent
product coverage.
