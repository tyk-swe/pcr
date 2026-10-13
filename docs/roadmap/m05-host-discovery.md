# M5: Host discovery

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M4](m04-target-planning.md) | [M10](m10-os-identification.md), [M11](m11-scan-informed-traceroute.md), [M13](m13-sctp-ip-protocol.md) |

Opt-in discovery and Linux acceptance are implemented; macOS/Windows native
acceptance remains open.

## Behavior and decisions

- `--discovery before|only|skip` uses `scan::discovery::Options` (default: none).
  `only` probes no scan ports; `before` defaults to responders-only (`--unresponsive-hosts scan` overrides).
- Probes are ICMP echo, TCP SYN (or connect with `--connect`), UDP, and local
  ARP/NDP (`neighbor`), sharing scan port exclusions, authorization, sequence
  space, packet/byte/probe/evidence budgets, and duration.
- Host records distinguish responsiveness (including target resets, refused
  sockets, and target port-unreachable) from `no_response` and router errors.
  Neighbor evidence distinguishes direct, cached, and `possible_proxy` on-link
  replies from routed `next_hop` gateways.
- `--reverse-dns` queries an explicit authorized DNS server under the remaining
  duration; PTR names and MACs remain unauthenticated observations.
- Introduced in output/v9 and retained in v15; see
  [host evidence](../scanner-evidence.md#host-observations) and
  [compatibility](../consumer-compatibility.md#output-family-v9).

## Independent discovery corpus and runtime route

Dataset 1.3.0 covers responsive, closed, silent, blocked, routed, and shared-link
dual-stack conditions. `discovery-native-evidence/v1` (`scripts/test-host-discovery-native.py`)
uses independently encoded immediate replies and reserved closed sockets, with
submission-start freshness eligibility (`transmit::Timing::freshness_marker()`).

Clean Linux acceptance at `e7f3e2efa7b47ba2ffa7e2818dbcc4d53eaef9e3` records 44
exercised cases, 36 typed refusals, and 168 bounded CLI commands
([evidence](evidence/m05/README.md)):

```sh
sudo -n env "PATH=$PATH" "CARGO_HOME=$HOME/.cargo" "RUSTUP_HOME=$HOME/.rustup" \
  python3 scripts/test-host-discovery-native.py \
  --reviewed-commit "$(git rev-parse HEAD)" --require-complete \
  --report target/validation/m5-linux/host-discovery.json
```

## Remaining platform gates

[Host-local run 37968418933](https://github.com/tyk-swe/pcr/actions/runs/37968418933)
(`2f7eaafbed809e2e5cae49b60176ec072a6f0897`) recorded macOS ARM loopback
contradictions, Windows unavailable raw paths, and macOS Intel cancellation;
host-local loopback also cannot isolate routed or shared-link topologies. M5
remains **In progress** until applicable macOS/Windows native gates pass or
have documented capability boundaries.
