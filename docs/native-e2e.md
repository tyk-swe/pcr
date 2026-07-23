# Linux native E2E testing

The native E2E harness provides an isolated baseline for PacketcraftR's Linux
networking commands. It owns this topology for one invocation:

```text
pcr-client <---- veth ----> pcr-router <---- veth ----> pcr-server
```

Every namespace and veth name contains the harness PID and a random suffix.
Concurrent invocations therefore have independent names even though their
addresses are intentionally identical inside their isolated namespaces.

The client-router link uses `10.203.0.0/30` and `fd70:6372:1::/64`. The
router-server link uses `10.203.0.4/30` and `fd70:6372:2::/64`. Client and
server receive explicit routes to the remote link, and the router has IPv4 and
IPv6 forwarding enabled while endpoint forwarding is disabled. No namespace
has a default route. Fixtures use only literal private/ULA addresses, so the
harness neither needs nor permits public DNS or external Internet access.

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
- `sysctl`;
- Python 3.9 or newer, using only the standard library;
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

## Independent fixtures and readiness

`fixtures/responders.py` opens IPv4 and IPv6 UDP and TCP listeners on
`pcr-server`. Only after all four sockets are bound does it connect to a unique
Unix readiness socket and report its exact listener set and PID. The harness
validates that message before running any case; it does not use a startup
sleep.

`fixtures/socket_client.py` runs in `pcr-client` and uses normal
standard-library sockets. It verifies:

- IPv4 UDP through `pcr-router`;
- IPv6 UDP through `pcr-router`;
- an IPv4 TCP connection through `pcr-router`;
- an IPv6 TCP connection through `pcr-router`.

Neither helper imports PacketcraftR or constructs/decodes packets with it.

## Lifecycle and diagnostics

The Python lifecycle owner handles success, assertions, child exits, partial
topology creation, and `SIGINT`, `SIGTERM`, or `SIGHUP`. It terminates every PID
in the dedicated server namespace before deleting namespaces, checks the host
for all generated interface and namespace names, and removes its temporary
readiness socket and responder logs. A successful run fails if any cleanup
step or leak check fails.

On a test failure, diagnostics are collected before teardown and printed to
stderr:

- `ip netns list` and detailed host/namespace link state;
- IPv4 and IPv6 addresses in all three namespaces;
- all IPv4 and IPv6 route tables;
- IPv4 and IPv6 neighbor tables;
- IPv4/IPv6 forwarding values;
- namespace PIDs;
- responder stdout and stderr;
- every executed command with its exit status.

Audit this path by intentionally failing one independent check:

```console
scripts/test-native-e2e --force-failure ipv4-udp
```

That command must exit nonzero, print diagnostics, and still leave no generated
namespace, veth, responder, readiness socket, or temporary directory.

## Layout and extension points

```text
scripts/test-native-e2e                 strict build-and-run entry point
tests/native_e2e/harness.py             lifecycle and result reporting
tests/native_e2e/cases/connectivity.py  independent baseline checks
tests/native_e2e/fixtures/              UDP/TCP responder and socket client
tests/native_e2e/support/               commands, topology, readiness, diagnostics
```

Future `send`, `capture`, `exchange`, `scan`, `dns`, `traceroute`, and `replay`
modules belong under `tests/native_e2e/cases/`. They receive `CaseContext`,
which exposes the already-built PacketcraftR binary, the topology, the
independent responders, and the audited command runner. The baseline remains
the independent verifier rather than making PacketcraftR verify itself.

## CI

The `Linux native namespace E2E` job in `.github/workflows/ci.yml` installs
iproute2, libpcap development files, and shellcheck; compiles the Python helpers;
then runs `scripts/test-native-e2e`. GitHub-hosted Ubuntu runners provide
passwordless non-interactive sudo. A runner that cannot create the topology
fails the job with the same prerequisite diagnostic as a local run.
