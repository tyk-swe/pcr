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
