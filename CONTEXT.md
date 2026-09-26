# PacketcraftR

Four-crate Rust workspace for authorized packet construction, capture, and
offline analysis: `packetcraftr-core` (packets, codecs, documents, filters),
`packetcraftr-netio` (provider contracts and native resources), `packetcraftr`
(live workflows, policy, evidence), and `packetcraftr-cli` (arguments,
rendering, machine output).

## Language

### Packets and captures

**Capture file**:
A pcap or pcapng file: its capture scope (interfaces, link types, timestamp
resolution) and the frames recorded under it.
_Avoid_: pcap (for both formats), savefile

**Permissive packet**:
A packet built in permissive mode that may break protocol rules on purpose.
Transmitting one needs both policy permission and a request opt-in.
_Avoid_: malformed (for packets built this way on purpose)

**Malformed bytes**:
Captured or decoded bytes that no codec could interpret, kept exactly as
they were received.
_Avoid_: permissive (for received bytes)

**Header walk**:
Locating link, VLAN, and IP headers directly in raw bytes, for edits and
checks a codec round trip would not reproduce faithfully (ADR 0004). Core has
one walker, `protocol::headers`; every such caller uses it.
_Avoid_: hand parsing, ad-hoc offsets

**Classification**:
The stable code, kind, and remediation that identify a failure in machine
output. Kinds are neutral (usage, packet, capability, I/O, policy, internal);
the CLI decides how each kind is published.
_Avoid_: CLI kind (for usage failures raised by libraries)

### Resources

**Limit**:
A configured ceiling on one resource, validated when it is set and never
silently lowered.
_Avoid_: budget, cap (for the ceiling)

**Budget**:
The allowance charged against a limit while work runs. Running out stops the
work with a classified failure; it is never evidence that something was absent.
_Avoid_: limit (for the running allowance)

### Live workflows

**Workflow**:
A policy-gated live operation run through the client: send, exchange, DNS,
scan, traceroute, fuzz, replay, or capture.
_Avoid_: engine, runner (for the operation as a whole)

**Client**:
The single entry point that holds the policy, protocol registry, clock, runtime,
and providers, and runs every workflow.
_Avoid_: authorizer, executor (as entry points)

**Request**:
The caller's validated intent for one workflow run.
_Avoid_: input, live options (for the whole intent)

**Plan**:
The bounded schedule of work a workflow derives from its request before any
traffic leaves.
_Avoid_: batch (for the whole schedule)

**Executor**:
The seam that carries out one approved step against providers and returns the
evidence that step produced.
_Avoid_: transmitter, runner

**Evidence**:
What was actually observed for a step: the exact packets sent and the frames
captured, validated before they reach a result.

**Exchange**:
Transmitting packets with capture armed first, then collecting the frames
correlated to them.
_Avoid_: calling a socket request/response with no capture an exchange; that
is a query

**Event**:
An incremental result a workflow publishes while it runs.
_Avoid_: progress, frame evidence (for published results)

**Report**:
The terminal result of one workflow run.
_Avoid_: set report, batch report, summary (for the terminal result)

### Live I/O

**Provider**:
A capability contract through which live workflows reach the network: routes,
interfaces, capture, transmission, and TCP connect. Holds no packet
interpretation or workflow policy.
_Avoid_: backend, resolver, sender (as contract names)

**System provider**:
The native implementation of a provider, selected for the build's platform.
_Avoid_: native provider, `SystemLayer2`-style per-variant names

**Backend**:
An OS- or library-specific native binding that a system provider dispatches to
(netlink, AF_ROUTE, IP Helper, libpcap, Npcap, raw IP sockets).
_Avoid_: provider (for a binding)

**Route plan**:
The passive choice of route, source address, and link for one packet, made
without discovery, capture, or transmission.
_Avoid_: route materialization (for the passive choice)

**Neighbor resolution**:
Active ARP/NDP discovery of a next hop's link address, composed from
transmission and capture. It is active discovery, so it requires authorization.
_Avoid_: neighbor lookup (implies a passive table read)

### Test vocabulary

**Contract test**:
A public-behavior regression test living in `crates/*/tests/`, named
`*_contracts.rs`. The default category for integration tests.
_Avoid_: "integration test" as a file-name signal; bare feature names
(`dhcp.rs`) that omit the suffix.

**Conformance test**:
A test asserting compliance with a published schema or wire format, named
`*_conformance.rs` (e.g. NDJSON and aggregate schema output).
_Avoid_: folding schema checks into contract tests. The shared parse helper
that validates output before a contract test reads it is a guard, not a schema
check.

**Matrix test**:
A test that enumerates an exhaustive combination space, named `*_matrix.rs`
(e.g. protocol codec coverage, published example schemas).

**Smoke test**:
A shallow sanity pass over real inputs such as fuzz corpora, named
`*_smoke.rs`.

**Native-isolated test**:
A test gated on `packetcraftr_test_netns` that runs under the isolated Linux
launcher, in `native_isolated.rs`. Not a contract test: it exercises real
kernel resources, not public API behavior.

**Common helpers**:
Shared integration-test helpers in `tests/common/`.
_Avoid_: `tests/support/` as a directory name.

**Test support**:
In-crate test helpers that must compile with the crate (shared buffers,
fixture constructors), in `test_support` modules: the crate's
`src/test_support.rs`, or one local to the module whose tests share it.
_Avoid_: `test_fixtures` as a module name.
