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

The feature profiles differ: no-default features keep native providers
disabled, the default enables interface enumeration and passive route lookup
(Unix enumeration reads the same route backend, so `native-interfaces`
requires `native-route` there), and all features enable every native provider.
The [CI workflow](.github/workflows/ci.yml) is the authoritative check set;
macOS and Windows skip the all-feature test run because their capture backends
need Npcap or a system libpcap.

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
