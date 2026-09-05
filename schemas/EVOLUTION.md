# Contract evolution

Aggregate `result` objects and their nested output records accept additional
properties. Consumers must ignore unknown fields. Shared record definitions
have the same semantics when used in NDJSON. Existing required fields, types,
units, meanings, enum names and ordering remain part of the v1 contract.
Adding optional output fields is compatible; removing or renaming fields,
changing their meaning, or extending a closed enum requires an explicit
breaking-change review and an appropriate schema version. Opening objects
does not open expert-code enums.

Envelope fields remain closed, including the aggregate/stream distinction,
sequence requirements, and success/error exclusivity. Stream-only event
objects retain their current contracts. Embedded packet documents and tagged
reflective field values remain strict, consistent with the separate packet
input schema. Input misspellings must still fail validation.

Published examples cover every declared output property. Aggregate conformance
tests check real serialized values, additive fields, required fields, types,
and envelope rejection. Enum tests continue to pin names and order.
`cargo semver-checks` separately checks Rust library API compatibility against
the PR base or previous main commit (the preceding commit for a manual CI
run); it does not validate JSON contracts. This gate applies the policy to
new changes. The existing unreleased changes include intentional breaks from
`v0.5.0-beta.2`; review the full release delta separately with:

```sh
cargo semver-checks check-release \
  -p packetcraftr-core -p packetcraftr-netio -p packetcraftr \
  --baseline-rev v0.5.0-beta.2 --all-features --release-type patch
```

The explicit patch-level check is necessary while versions are prereleases:
the tool otherwise assumes a major release and skips compatibility lints.
An intentional breaking release must explicitly revise this gate as part of
its version and migration-policy review.

# Cryptographic dependencies

The optional `packetcraftr-core/decrypt` feature owns RustCrypto AES-GCM,
ChaCha20-Poly1305, and HKDF dependencies. Existing SHA-256 support remains
available for fingerprints. Crypto stays in the runtime-neutral core; live
authorization and finite traffic budgets remain workflow responsibilities.
Enabling the feature currently supplies dependencies, not TLS decryption,
QUIC, or anonymization commands.

# Runtime protocol schema lifetime

The protocol-document loader will retain the existing static `Schema` and
field-name API. Validated runtime schemas and their names are allocated once
per process and deliberately leaked only when registration commits. A
process-wide registry must reuse identical definitions and reject conflicting
names. Repeated loads must not produce repeated leaks.

`DocumentLimits` bounds parsing before allocation: input bytes, protocol and
field-name lengths, fields per protocol, nesting, nodes, list items, and
retained payload bytes. Registration must also charge cumulative retained
schemas and names against a process-wide budget derived from those limits;
per-document limits alone do not bound repeated loads. All validation,
discriminator resolution, checked layout arithmetic, and budget reservations
must succeed before any permanent allocation. A failed load publishes no
partial registry and leaks no schema. This is the Phase 2 implementation
contract; no runtime loader is exposed yet.
