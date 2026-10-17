# Three starting tasks

Commands assume `packetcraftr` on `PATH`; see [installation](../README.md#install).
Use `packetcraftr --help` to find the workflow groups.
`-h` shows common options; `--help` shows full help; `--verbose` expands text evidence.
Library callers should [pin a reviewed revision](consumer-compatibility.md#rust-api-adoption).

## 1. Build a fixture and test one property

```sh
packetcraftr --output hex packet build --packet 'raw(text=hello)'
```

This emits `68656c6c6f`, without traffic. For IPv4/UDP, use `packet build --packet-file`
with [the structured fixture](../examples/documents/packet-ipv4-udp.json).
Invalid fields/values fail before transmission.

Run the [forwarding harness](verification-contract.md).
It generates checksummed captures, expected transformations, intentional violations,
missing evidence, and output-budget controls. Read observed_verdict and test_contract:
a deliberate forwarding fail can be a passing regression. Choose a stable identity
[independent of the tested property](verification-contract.md#identity-is-not-the-property-under-test).

## 2. Investigate a capture without losing evidence

```sh
packetcraftr --resource-preset ci-v1 --resource-diagnostics --output ndjson \
  analyze http examples/captures/http-stream.pcap > http.ndjson
packetcraftr analyze stats examples/captures/http-stream.pcap --table overview
packetcraftr analyze stats examples/captures/http-stream.pcap --table conversations --sort bytes --top 10
packetcraftr --output csv analyze stats examples/captures/http-stream.pcap --table endpoints > endpoints.csv
packetcraftr --resource-preset ci-v1 --resource-diagnostics --output ndjson \
  analyze http2 examples/captures/http2-multiplexed.pcapng
packetcraftr --output json analyze http2 examples/captures/http2-upgrade.pcapng --stream tcp:0
```

Use [statistics](statistics.md) for capture totals, traffic leaderboards, and CSV exports.

`analyze http` is HTTP/1-only; `analyze http2` handles cleartext prior knowledge/h2c, not TLS
decryption. `tcp:INDEX` selects a conversation, not an HTTP/2 stream. Defaults
inspect ports 80/8080; repeat `--http2-port` for others. DATA bodies are discarded.
Read frames/messages/issues and final connections plus terminal complete/error.
Later gaps or GOAWAY can qualify earlier complete messages. Refused/incomplete
h2c preserves exact HTTP/1 evidence without invented streams.

Lower `--max-frames` to inspect a controlled failure. Filtered input still counts;
raise only the specific finite ceiling justified by diagnostics.
Parse/resource failure does not prove message absence. Two captures can use
`analyze verify-forwarding`; [consumer rules](consumer-compatibility.md) reject incomplete streams.

### Selecting and saving evidence

`files read --filter`, `--frames`, `--every`, and inclusive epoch bounds select physical
frames; `files export --stream tcp:INDEX` keeps a scoped conversation and contributing
fragments. Source frame numbers/budgets survive selection. Epoch bounds exclude
untimestamped frames and assume no time order.

Unselected, unnormalized `files read` rewrites capture bytes exactly. `--normalize`
discards comments/unknown blocks/options/sections but rejects declared FCS and
inexact timestamps. PCAP additionally needs a nonempty single-interface/link-type
selection without direction metadata and with compatible snapshot/precision;
otherwise use PCAPNG. Stdout may be partial on error. Staged export/merge/rewrite
publishes only on success and never overwrites a destination.

Readers accept stdin (`-`) and gzip/Zstd by magic. Merge/verification admit one
stdin input; live replay is file-based. Cooperative duration checks cannot interrupt
blocked reads: [isolate untrusted captures](analysis-resources.md#hosting-untrusted-captures-with-a-hard-stop).

## 3. Run an authorized diagnostic in an isolated lab

Start with passive interfaces/routes. Backend, profile, and privileges determine
availability; owner authorization is required independently of flags.
Finite budgets, final-wire policy, route/interface, and MTU checks apply.
`--allow-destination ADDRESS[/PREFIX]` only narrows permission (canonical prefixes);
public destinations still need separate opt-in. Read each command's help.
Explicit `network identify` claims are neither authentication nor vulnerabilities.

Linux raw I/O usually needs root/CAP_NET_RAW; macOS Layer 2 needs BPF access and
cannot send complete-header raw IPv6. Windows Layer 2 needs Npcap 1.88; raw I/O
usually needs administrator rights and may reject non-local UDP sources.
Containers need interfaces/routes/privileges in the same namespace.

After [isolated Linux setup](native-validation.md#isolated-linux-setup):

```sh
python3 scripts/test-native-isolated.py --binary target/release/packetcraftr
```

Never use production endpoints to make tests green. Worker permits survive
timeout/cancellation through cleanup; arbitrary providers/callbacks are cooperative.
Native BPF runs before capture queues/budgets, display filters after capture.
Retain hashes, tool/settings, capture point/window, and acquisition unknowns;
review payload-bearing bundles before sharing.
