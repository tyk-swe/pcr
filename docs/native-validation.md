# Capability and validation matrix

Only retained reports for the exact revision establish execution. Compilation,
skipped checks, and unavailable paths do not establish runtime coverage.

| Check | Environment | Retained inventory |
| --- | --- | --- |
| Public integration tests | Linux, macOS, Windows CI | 46 Rust tests; portable and native feature profiles |
| Service identification | IPv4 and IPv6 loopback | HTTP and HTTPS, current-schema NDJSON; one all-features build |
| Decoder oracle | Offline Linux CI | `spec-vectors` (9 frames) and `tls-handshake` (8 frames), including JA3 |
| Native exchange | Fresh Linux user/network namespace | `loopback_exchange` using the all-features CLI |
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

No separate Rust native test executable is required. The internal validation
report uses `schema_version: 2`. Release validation requires the complete named
inventory, successful scenario and launcher exit codes, distinct positive
namespace identifiers, clean exact-commit provenance, and the CLI binary digest.
Decoder evidence additionally requires the pinned TShark identity and digest,
all comparison fields, capture digests and frame counts, no mismatches, and JA3
agreement. Missing or failed evidence blocks release validation.
