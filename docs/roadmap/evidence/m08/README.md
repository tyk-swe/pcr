# M8 service identification evidence

The implementation uses ordinary TCP and connected UDP sockets, including in
native feature builds. Identification does not invoke raw capture, routing,
neighbor discovery or injection. Its applicable platform seam is ordinary socket
I/O, peer identity, timeout/cancellation behavior and bounded response retention;
Windows additionally retains the prefix reported with Winsock `WSAEMSGSIZE`.

The independent conditions are recorded in
[`scanner-corpus.v1.json`](../../../scanner-corpus.v1.json), dataset version 1.4.0.
Core [fixture contracts](../../../../crates/packetcraftr-core/tests/integration/service_identification_contracts.rs)
cover known SSH/HTTP/DNS, unfamiliar services, conflicting products/versions,
misleading claims, malformed replies, truncation, reproducible matching and
bounded documents. Workflow [behavior contracts](../../../../crates/packetcraftr/tests/integration/identify_contracts.rs)
exercise budgets, final endpoint authorization, byte accounting, exclusions,
intensity and portable loopback sockets. Netio
[application I/O contracts](../../../../crates/packetcraftr-netio/tests/integration/application_io_contracts.rs)
exercise partial timeout evidence, peer filtering, UDP prefix truncation and
absence of retransmission. CLI
[contract tests](../../../../crates/packetcraftr-cli/tests/integration/identify_contracts.rs)
cover user invocation, exact bytes, claims, confidence, provenance and publication
contracts against the independently versioned output family.

The [cross-platform acceptance runner](../../../../scripts/test-service-identification.py)
checks unknown/ambiguous machine output as well as bounded, isolated loopback
fixtures for both IP families, with each supported feature profile built
separately. Reports identify
the exercised commit, operating system, architecture, profile and fixture
outcomes. Compilation and unavailable scenarios are not passing runtime evidence.
The reports and exact local validation results will be linked here after the
reviewed-revision runs complete.
