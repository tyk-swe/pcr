# Contributing to PacketcraftR

PacketcraftR welcomes focused fixes, features, and documentation changes.
Report suspected vulnerabilities through [SECURITY.md](SECURITY.md), not a
public issue.

[AGENTS.md](AGENTS.md) holds the repository layout, the check commands, the
coding and lint rules (`unsafe`, `#[expect]`, indexing, and arithmetic), and
the commit and pull request conventions. This file covers what it leaves out.

## Setup and checks

Run the checks from AGENTS.md that cover your change, with locked
dependencies. The project does not configure a compiler wrapper or linker, so
Cargo and the Rust toolchain use their platform defaults.

The feature profiles differ: `no-default-features` keeps native providers
disabled; the default enables interface enumeration and passive route lookup;
`native-interfaces` directly encodes its dependency on `native-route`; `native-layer2`
and `native-layer3` both imply `native-interfaces` and `native-route`.
The `pcap-free` profile (`--no-default-features --features native-route,native-layer3`)
supports routing and raw layer 3 without libpcap. All features enable every native provider.
Use `./scripts/check-features.sh` to check the supported public feature matrix.
The [CI workflow](.github/workflows/ci.yml) is the authoritative check set;
macOS and Windows test `no-default`, `default`, and `pcap-free`, while their
all-feature builds run `cargo check`.

## Architecture

Cargo manifests and `cargo metadata` are the source of truth for packages,
features, and dependencies. Keep the graph acyclic. In particular, the core
crate must remain independent of native I/O and live workflows so offline
analysis cannot acquire a resolver, route, capture, or transmission seam.

## Issues and pull requests

Use the general issue form for portable or offline defects and the native form
for interfaces, routes, capture, injection, raw sockets, or live workflows.
Include the version, feature profile, platform, minimal reproduction, expected
and actual results, and sanitized diagnostics. Never post production captures,
credentials, public-target details, or exploit information.

On top of the pull request rules in AGENTS.md:

- keep mechanical refactoring separate from behavior changes;
- record work you deliberately left out in [TODOS.md](TODOS.md), with the
  change that deferred it;
- review the full diff yourself first, and get review from every affected
  owner on a cross-boundary change; and
- cover the relevant unavailable-backend, permission, stale-interface,
  timeout, cancellation, partial-I/O, queue, accounting, and cleanup paths in
  native networking changes.
