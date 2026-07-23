# Linux native E2E testing

The native E2E harness exercises PacketcraftR's Linux networking commands in
seven isolated cases. Each case owns this topology for its full lifecycle:

```text
pcr-client <---- veth ----> pcr-router <---- veth ----> pcr-server
```

Every namespace and veth name contains the harness PID and a random suffix.
Each case also receives a distinct `10.203.N.0/30` and `10.203.N.4/30` pair
and distinct `fd70:6372::/64` segments. Client and server receive explicit
routes to the remote link, and the router has IPv4 and IPv6 forwarding enabled
while endpoint forwarding is disabled. No namespace has a default route.
Fixtures use only literal private/ULA addresses, so the harness neither needs
nor permits public DNS or external Internet access.

## Local invocation

Prime sudo's credential cache, then use the repository entry point:

```console
sudo -v && scripts/test-native-e2e
```

The script uses non-interactive sudo only for namespace operations. Cargo runs
as the invoking user, builds the all-feature `packetcraftr` binary exactly once,
and exports its absolute path as `PACKETCRAFTR_BIN` to all later test cases.
Running as root also works without sudo:

```console
scripts/test-native-e2e
```

The dedicated command is strict. A missing tool, unsupported namespace
operation, or insufficient privilege exits nonzero with a prerequisite error;
it never converts the run into a success or skip. Probe prerequisites alone
with:

```console
scripts/test-native-e2e --check-prerequisites
```

Ordinary unprivileged `cargo test` does not discover this privileged Python
harness.

## Prerequisites

- Linux with network namespaces, veth, IPv4, and IPv6 enabled;
- `ip` from iproute2;
- `ethtool`, used to disable veth offloads so libpcap sees materialized
  checksums and packet boundaries;
- `kill`, used through the selected privilege boundary for process-group and
  namespace teardown;
- `sysctl`;
- Python 3.9 or newer with `jsonschema` Draft 2020-12 support;
- Cargo and the repository's pinned Rust toolchain;
- `libpcap` development files for the all-feature build
  (`libpcap-dev` on Ubuntu/Debian);
- sufficient authority to create named namespaces and veth devices, configure
  addresses/routes, and change namespace sysctls. Root is the portable option;
  capability-based setups need at least `CAP_NET_ADMIN` plus permission to
  create and mount named namespaces, commonly requiring `CAP_SYS_ADMIN`.

The prerequisite probe creates and removes a throwaway namespace and veth pair,
sets IPv4/IPv6 forwarding inside it, and checks for leaks. This tests actual
host behavior instead of inferring support from the effective UID.

## Native cases and independent fixtures

`fixtures/responders.py` opens IPv4 and IPv6 UDP and TCP listeners on
`pcr-server`. Only after all four sockets are bound does it connect to a unique
Unix readiness socket and report its exact listener set and PID. The harness
validates that message before running any case; it does not use a startup
sleep.

For each UDP request, the fixture reports the exact kernel-observed address
tuple and payload through a separate event barrier. Depending on the case, it
echoes from the requested port, receives without replying, or replies from a
deliberately different source port. The fixture uses only Python
standard-library sockets and never imports PacketcraftR.

The seven command-specific cases cover:

- IPv4 and IPv6 route planning without interface or source hints;
- IPv4 and IPv6 native Layer 3 send, verified by the independent receiver;
- a successful native UDP exchange, including live capture and correlation;
- a bounded exchange timeout with a fixture-confirmed request;
- native capture of a wrong-source-port UDP reply and matcher rejection.

Every JSON result is validated against the committed output-v1 schema with an
independent Draft 2020-12 validator before semantic assertions run.

## Lifecycle and diagnostics

The Python lifecycle owner handles success, assertions, child exits, partial
topology creation, and `SIGINT`, `SIGTERM`, or `SIGHUP`. It terminates every PID
in each dedicated namespace before deleting namespace names, checks the host
for all generated interface and namespace names, and removes its temporary
readiness socket and responder logs. Timed-out and interrupted commands run in
isolated process groups that are terminated through the same privilege
boundary. A successful run fails if any cleanup step or leak check fails.

On a test failure, diagnostics are collected before teardown and printed to
stderr:

- `ip netns list` and detailed host/namespace link state;
- IPv4 and IPv6 addresses in all three namespaces;
- all IPv4 and IPv6 route tables;
- IPv4 and IPv6 neighbor tables;
- IPv4/IPv6 forwarding values;
- namespace PIDs;
- PacketcraftR argv, stdout, stderr, exit status, and elapsed time;
- fixture stdout and stderr;
- every executed command with its exit status.

Audit this path by intentionally failing one native case:

```console
scripts/test-native-e2e --force-failure route-ipv4
```

That command must exit nonzero, print diagnostics, and still leave no generated
namespace, veth, fixture process, Unix socket, or temporary directory.

## Layout and extension points

```text
scripts/test-native-e2e                 strict build-and-run entry point
tests/native_e2e/harness.py             lifecycle and result reporting
tests/native_e2e/cases/route.py         IPv4/IPv6 route planning
tests/native_e2e/cases/send.py          IPv4/IPv6 native Layer 3 sends
tests/native_e2e/cases/exchange.py      success, timeout, and matcher rejection
tests/native_e2e/fixtures/              independent UDP/TCP responder
tests/native_e2e/support/               topology, barriers, schema, diagnostics
```

Future `capture`, `scan`, `dns`, `traceroute`, and `replay` modules belong
under `tests/native_e2e/cases/`. They receive `CaseContext`, which exposes the
already-built PacketcraftR binary, the case topology, independent fixtures,
and the audited command runner. PacketcraftR must not be used to verify its own
native output.

## CI

The `Linux native namespace E2E` job in `.github/workflows/ci.yml` installs
ethtool, iproute2, libpcap development files, Python jsonschema, and shellcheck;
compiles the Python helpers; exercises direct, prefixed, and privileged
process-tree timeout cleanup; then runs `scripts/test-native-e2e`. GitHub-hosted
Ubuntu runners provide passwordless non-interactive sudo. A runner that cannot
create the topology fails the job with the same prerequisite diagnostic as a
local run.
