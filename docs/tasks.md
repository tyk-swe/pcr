# Three starting tasks

Build the portable CLI from a checkout with the pinned toolchain:

```sh
cargo build --locked -p packetcraftr-cli --no-default-features
```

Use `target/debug/packetcraftr` below, or the installed `packetcraftr` executable.
For library use, see [revision-pinned consumers](consumer-compatibility.md).

## 1. Build a fixture and test one property

```sh
target/debug/packetcraftr --output hex build --packet 'raw(text=hello)'
```

The bytes are `68656c6c6f`. For a structured IPv4/UDP packet, start with
`examples/documents/packet-ipv4-udp.json` using `build --packet-file`.
Unknown fields or invalid recipe values fail before transmission; these
commands do not send traffic.

Then run the controlled [forwarding regression harness](verification-contract.md).
It generates checksummed captures, expected transformations, deliberate
violations, missing-field evidence, and output-budget controls. Inspect both
`observed_verdict` and `test_contract`: an intentional violation is expected to
produce a forwarding fail and a successful regression test.

Do not use a property that may change as the sole identity for testing that
change. Use a stable case identifier and an independent preservation check.

## 2. Investigate a capture without losing evidence

```sh
target/debug/packetcraftr --resource-preset ci-v1 --resource-diagnostics \
  --output ndjson http examples/captures/http-stream.pcap > http.ndjson
target/debug/packetcraftr --output json stats examples/captures/http-stream.pcap
```

HTTP message records identify framing/status and physical source evidence.
Read the terminal completion or error as well as individual messages. A parse,
capture, or resource limit is not proof that an application message was absent.

For an ordinary failure, lower `--max-frames` below the physical capture count.
Filtered-out input still counts; adding a display filter does not bypass that
limit. Inspect resource diagnostics, then raise the specific finite ceiling or
select an appropriately bounded input. Do not blindly raise every budget.

For two captures, use `verify-forwarding` with explicit identity and checks.
Its verdict is observational, not a device-loss or latency measurement.
The [machine consumer](consumer-compatibility.md) rejects incomplete streams.

## 3. Run an authorized diagnostic in an isolated lab

Begin with passive `interfaces` and `routes` inspection. Live adapters depend on
the selected native feature profile, installed backend, and privileges.
Authorization comes from the system/network owner, not from a command-line flag.

On a disposable Linux runner, follow the namespace setup in
[native validation](native-validation.md), then run the existing isolated
native harness. It checks that the namespace differs from its parent and has
only loopback before any native scenario runs. Do not point an active example
at a production endpoint to obtain a green test.

On a separately authorized loopback adapter, the opt-in
`scripts/check-native-capture.py` checks activation, explicit settings, repeated
shutdown/reopen, and filter failure. It does not send traffic, does not configure
drivers, and does not certify cancellation or active networking.

Retain input/output hashes, tool identity, capture point, settings, observation
window, and acquisition unknowns with any real regression result. Review bundles
before sharing: packet bytes can contain sensitive information.
