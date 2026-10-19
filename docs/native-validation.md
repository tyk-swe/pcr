# Capability and validation matrix

Only retained reports for the exact revision establish execution. Compilation,
skipped checks, and unavailable paths do not establish runtime coverage.

| Check | Environment | Retained inventory |
| --- | --- | --- |
| Public integration tests | Linux, macOS, Windows CI | Rust integration suites and focused implementation regressions; portable and native profiles |
| Service identification | IPv4 and IPv6 loopback | HTTP and HTTPS, current-schema NDJSON; one all-features build |
| Decoder oracle | Offline Linux CI | `spec-vectors` (9 frames) and `tls-handshake` (8 frames), including JA3 |
| Native exchange | Fresh Linux user/network namespace | `loopback_exchange` using the all-features CLI |
| Namespace lifecycle | Fresh Linux user/network namespace | Separate opt-in Rust harness; more than 16 sequential namespaces, concurrent requests, bounded ownership and loopback recovery. Requires its own retained runtime report. |
| Public consumer | Detached portable Cargo project | Public provider composition |

## Before merge

PRs run the checksum-pinned decoder oracle (`scripts/check-decode-oracle.py`).
Privileged Linux CI runs after integration, weekly, or manually. Review the full
immutable commit before dispatching `native-review.yml`. The workflow uses the
`native-review` environment; configure its required reviewers in repository
settings. Do not use `pull_request_target` or persistent sensitive runners.

The current native inventory covers one IPv4 loopback exchange. It does not
establish privileged macOS/Windows coverage or broader native scenario coverage.

## Isolated Linux setup

Install `libpcap-dev`, `iproute2`, `util-linux`, and `uidmap` on a disposable runner:

```sh
cargo build --locked --release -p packetcraftr-cli --all-features
python3 scripts/test-native-isolated.py --binary target/release/packetcraftr
```

The launcher refuses execution outside a fresh, loopback-only network namespace.
On hosts that require elevated namespace setup, authorize `root:<uid>:1` in
`/etc/subuid` and `/etc/subgid` for `util-linux < 2.40`, then run:

```sh
sudo python3 scripts/test-native-isolated.py --binary target/release/packetcraftr
```

The loopback exchange uses no separate Rust native test executable. Its internal
validation report uses `schema_version: 1`. Release validation requires the complete named
inventory, successful scenario and launcher exit codes, distinct positive
namespace identifiers, clean exact-commit provenance, and the CLI binary digest.
Decoder evidence additionally requires the pinned TShark identity and digest,
all comparison fields, capture digests and frame counts, no mismatches, and JA3
agreement. Missing or failed evidence blocks release validation. Successful
reports must also carry a nonempty CLI version and cannot retain execution or
responder errors. The release gate checks the selected run's exact commit,
push event, completion, success, positive run ID, and repository URL rather than
relying on API query filters alone.

The Python native validators use explicit exceptions, not optimization-removable
assertions. An exchange must contain one authorized send followed by one
attributed exact reply and a successful terminal with no unanswered request.
A lifecycle launcher failure cannot preserve a child's `passed` status.
Report writers reject input aliases, clear stale reports before a new attempt,
and publish complete UTF-8 JSON atomically. These checks do not replace the
privileged runtime lane; mocked Python regressions are not native evidence.

## Namespace lifecycle regression (N1)

The separate lifecycle harness compiles a privileged Linux test as visibly
ignored in ordinary `cargo test`. It never turns unavailable privileges into a
passing test. Build its exact executable and run the guarded launcher on a
disposable runner:

```sh
cargo test --locked -p packetcraftr-netio --all-features --lib --no-run \
  --message-format=json > target/netio-native-build.jsonl
python3 scripts/test-native-namespace-lifecycle.py \
  --build-report target/netio-native-build.jsonl \
  --report target/native-namespace-lifecycle.json
```

The launcher pins the parent namespace descriptor and refuses an unfresh or
non-loopback-only child. Only the established native platform test boundary
changes the test thread's namespace, restores it with an owned guard, and uses
production route workers. It checks resident services, root admissions and
namespace descriptors, then eligible control work and TCP loopback after churn.
The existing gated native-review lane builds and runs it in its isolated lab;
this does not dispatch that workflow or change the loopback release inventory.

Its standalone `packetcraftr.namespace-lifecycle/v1` report records the exact
test executable and launcher digests, source revision/dirty state, namespace
identities and measured ownership bounds. It is distinct from the retained
`schema_version: 1` loopback report. Current local execution is blocked by
`unshare: write failed /proc/self/uid_map: Operation not permitted`; compilation,
ordinary ignored status and guard refusal are not native runtime coverage.
Namespace identity reuse and real OS initialization failure remain unexercised;
the deterministic registry regressions cover those ownership/error paths only
at their injected boundary. Re-run the explicit launcher with authorized
namespace support before claiming native lifecycle acceptance.
