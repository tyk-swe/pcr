# M5: Host discovery

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M4](m04-target-planning.md) | [M10](m10-os-identification.md), [M11](m11-scan-informed-traceroute.md), [M13](m13-sctp-ip-protocol.md) |

Opt-in discovery and Linux acceptance are implemented. Broader macOS/Windows
native acceptance is still open; an implementation or skipped route is not parity.

## Behavior and decisions

- `--discover before|only|skip` uses `scan::discovery::Options`; default behavior
  remains no discovery. `only` needs no port scan; before-scan defaults to
  responders-only, with an explicit scan-all strategy available.
- Strategies are ICMP echo, SYN, UDP, explicitly selected ordinary TCP sockets,
  and local ARP/NDP. No hidden fallback, vendor lookup, or additional family is
  introduced. Discovery ports share scan selection/exclusions.
- One policy, packet/byte/probe/evidence allowance, preparation ceiling, and
  invocation duration cover discovery and scan. Authorization precedes resolution
  and final endpoint/wire checks precede every active send. Partial work remains
  stage-tagged evidence; skipped attempts invent no network result.
- Host records distinguish responsiveness from uncertain silence. Target resets,
  refused sockets, and target port-unreachable replies can prove responsiveness;
  router errors retain probes but produce no target response reason.
- Neighbor evidence distinguishes direct, cached, and possible-proxy observations.
  Routed gateway addresses stay under `next_hop`, never target identity.
  Shared-link/proxy observations and MACs remain unauthenticated.
- Reverse names are opt-in through an explicit authorized DNS server, under the
  remaining invocation budget. Repeated PTR answers/sources are retained; names
  are observations, not verified identity. No vendor database is bundled.
- Output/v9 introduced hosts, stage discriminators, and discovery plans; current
  v13 retains them. See [host evidence](../scanner-evidence.md#host-observations)
  and [compatibility](../consumer-compatibility.md#output-family-v9).

## Independent discovery corpus and runtime route

Dataset 1.3.0 adds independently authored responsive, closed, silent, blocked,
routed, and shared-link conditions in both IP families. Controlled contracts
cover authorization, budgets, DNS/socket failures, omissions, and streaming.
The separate `discovery-native-evidence/v1` runner uses independently encoded,
immediate responses and reserved closed sockets; compilation/skips do not pass.

The successful exact native submission interval begins at
`transmit::Timing::freshness_marker()` after socket preparation and ends when
acceptance returns. Immediate replies inside it are eligible even before the
send call returns. Stale or missing monotonic ingress remains ineligible.
Neither marker is a wire timestamp, receipt guarantee, or identity proof.

Clean Linux acceptance at `e7f3e2efa7b47ba2ffa7e2818dbcc4d53eaef9e3`
records 44 exercised cases, 36 actual typed refusals, and 168 bounded CLI commands:
[retained report](evidence/m05/README.md). Fixtures add no artificial response
delay. Capability-disabled profiles remain incomplete for active capture despite
correct refusal behavior.

Reproduce on a disposable, properly isolated Linux runner:

```sh
sudo -n env "PATH=$PATH" "CARGO_HOME=$HOME/.cargo" "RUSTUP_HOME=$HOME/.rustup" \
  python3 scripts/test-host-discovery-native.py \
  --reviewed-commit "$(git rev-parse HEAD)" --require-complete \
  --report target/validation/m5-linux/host-discovery.json
```

Both reviewed native workflows accept `scenario=host_discovery`. Follow
[native prerequisites](../native-validation.md); do not broaden permissions or
send externally to make a report green.

## Remaining platform gates

[Host-local run 37968418933](https://github.com/tyk-swe/pcr/actions/runs/37968418933)
at `2f7eaafbed809e2e5cae49b60176ec072a6f0897` retained macOS ARM closed-socket
timeouts/raw-loopback contradictions, Windows unavailable raw paths, and macOS
Intel cancellation after an explicit request to skip environment checks.
Those outcomes are not passes. Host-local loopback also cannot establish routed
or shared-link isolation. No remote traffic or driver installation is authorized.

M5 remains **In progress** until its independent native inventory passes on
applicable macOS/Windows routes, with failures and supported limitations recorded.
Linux success does not close broader M2/M3/M7 or later inference gates.
