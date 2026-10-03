# Three starting tasks

Commands below assume `packetcraftr` is on `PATH`; see
[install or build](../README.md#install). For library use, see
[revision-pinned consumers](consumer-compatibility.md).

## 1. Build a fixture and test one property

```sh
packetcraftr --output hex build --packet 'raw(text=hello)'
```

The bytes are `68656c6c6f`. For a structured IPv4/UDP packet, start with
`examples/documents/packet-ipv4-udp.json` using `build --packet-file`.
Unknown fields or invalid recipe values fail before transmission; these
commands do not send traffic.

Then run the controlled [forwarding regression harness](verification-contract.md#reproduction-bundle).
It generates checksummed captures, expected transformations, deliberate
violations, missing-field evidence, and output-budget controls. Inspect both
`observed_verdict` and `test_contract`: an intentional violation is expected to
produce a forwarding fail and a successful regression test. Choose the case
identity as [the contract](verification-contract.md#identity-is-not-the-property-under-test)
describes: a stable identifier, independent of the property under test.

## 2. Investigate a capture without losing evidence

```sh
packetcraftr --resource-preset ci-v1 --resource-diagnostics \
  --output ndjson http examples/captures/http-stream.pcap > http.ndjson
packetcraftr --output json stats examples/captures/http-stream.pcap
```

HTTP message records identify framing/status and physical source evidence.
Read the terminal completion or error as well as individual messages. A parse,
capture, or resource limit is not proof that an application message was absent.

For cleartext HTTP/2, inspect the multiplexed and h2c examples with the separate
`http2` command; `http` remains HTTP/1-only:

```sh
packetcraftr --resource-preset ci-v1 --resource-diagnostics --output ndjson \
  http2 examples/captures/http2-multiplexed.pcapng
packetcraftr --output json http2 examples/captures/http2-upgrade.pcapng --stream tcp:0
```

`--stream tcp:INDEX` selects a TCP conversation, not an HTTP/2 stream ID.
Ports 80 and 8080 are inspected by default; repeat `--http2-port PORT` for
other cleartext services. TLS application data is unsupported and is not
decrypted. Read `http2_frame`, `http2_message`, `http2_issue`, and the final
`http2_connection` assessment as well as the terminal completion/error.
A complete message does not override later evidence. A later GOAWAY that
excludes an already-emitted request produces a sourced `goaway_unprocessed`
issue for that stream; consumers must apply it alongside the earlier message.
An unaccepted h2c offer is preserved as `refused_upgrade` evidence when declined,
or `incomplete_upgrade` at termination, without inventing an HTTP/2 stream.
DATA bodies are counted and discarded.

For an ordinary failure, lower `--max-frames` below the physical capture count.
Filtered-out input still counts; adding a display filter does not bypass that
limit. Inspect resource diagnostics, then raise the specific finite ceiling or
select an appropriately bounded input. Do not blindly raise every limit.

For two captures, use `verify-forwarding` with explicit identity and checks; the
[machine consumer](consumer-compatibility.md) rejects incomplete streams.

## 3. Run an authorized diagnostic in an isolated lab

Begin with passive `interfaces` and `routes` inspection. Live adapters depend on
the selected native feature profile, installed backend, and privileges.
Authorization comes from the system/network owner, not from a command-line flag.

On a disposable Linux runner, follow the setup in
[native validation](native-validation.md#isolated-linux-setup), then run the
isolated harness against a full-native build:

```sh
python3 scripts/test-native-isolated.py --binary target/release/packetcraftr
```

Do not point an active example at a production endpoint to obtain a green test.
On a separately authorized loopback adapter, the opt-in
`scripts/check-native-capture.py` covers passive capture only; its scope is in
[native validation](native-validation.md).

Retain input/output hashes, tool identity, capture point, settings, observation
window, and acquisition unknowns with any real regression result. Review bundles
before sharing: packet bytes can contain sensitive information.
