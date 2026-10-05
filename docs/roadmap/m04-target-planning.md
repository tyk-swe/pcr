# M4: Target planning

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | [M1][m1] | [M5][m5] |

PacketcraftR already bounds target expansion, deduplicates, applies numeric
exclusions, and filters address families. Targets reach a scan only as
positional arguments, there is no way to see the resulting plan without running
it, and a link-local IPv6 address loses its interface scope on the way to a
socket. An authorized inventory is usually a file, and an operator needs to
check what a scan would touch before it touches anything.

This milestone adds bounded manifests, a list mode that sends nothing, and
scoped IPv6 targets, without changing how targets are authorized.

## Outcome

- Targets and exclusions can be supplied from bounded files or standard input,
  with the same authorization and selection as positional arguments.
- A list mode publishes the scan plan (addresses, families, and where each
  came from) without sending a target or neighbor packet.
- A scoped IPv6 target keeps its interface or zone identity from declaration to
  the socket or route that uses it.

## Baseline

| | PacketcraftR at `22c7d182d577` | Nmap reference |
| --- | --- | --- |
| Declarations | Positional IP addresses, hostnames, and bounded CIDRs; repeatable numeric `--exclude`; `--max-targets` (default 1,024) and `--family` ([scan arguments][scan-args], [selection][target-selection], [admission][target-admission]) | Hostnames, addresses, CIDRs, octet ranges, exclusions ([target specification][nmap-targets]) |
| Files and stdin | None for targets or exclusions | `-iL` and `--excludefile` ([target specification][nmap-targets]) |
| Listing | [`plan`][route-plan] performs passive route planning for one packet; it is not a scan manifest | `-sL` lists targets ([host discovery][nmap-discovery]) |
| Hostnames | Resolution is opt-in; every selected authorized answer is considered ([target model][target-model]) | The first resolved address unless `--resolve-all` is given ([target specification][nmap-targets]) |
| Scoped IPv6 | [`Target`][target-model] holds an `IpAddr` or hostname with no zone; [connect planning][connect-engine] builds numeric socket endpoints without scope | Zone-qualified non-global addresses ([target specification][nmap-targets]) |

## Invariants

- Numeric and CIDR authorization, hostname authorization, exclusions, and
  family selection behave identically for every input form.
- A manifest can only declare targets the policy would accept as arguments. It
  is not a way to widen authorization.
- Input is untrusted: size, line count, and expansion are bounded before any
  target is admitted.

## Scope

### M4.1 Target and exclusion manifests

- Bounded ingestion of target and exclusion declarations from a file or from
  standard input.
- Deterministic deduplication across positional arguments and manifests.
- Provenance: each selected target records the input that declared it.
- Malformed entries, oversized input, and duplicate declarations are reported
  before active work, with the offending source and position.

### M4.2 Scan list and plan mode

- A bulk mode that publishes the selected targets and their provenance, and
  sends no target or neighbor packets when the declarations are numeric.
- It is distinct from today's passive packet-route [`plan`][route-plan], which
  keeps its meaning.
- Hostname resolution stays an explicit opt-in. When it runs, the output says
  so; resolution is never presented as a network-free operation.

### M4.3 Scoped IPv6 targets

- A target declaration may carry an interface or zone for a non-global IPv6
  address.
- The scope is part of the target's identity through authorization, selection,
  and deduplication.
- Raw and ordinary-socket paths both honor the scope. A missing or ambiguous
  scope fails before active work.

## Non-goals

- Nmap's target grammar. Octet ranges and hostname/CIDR shorthand are not
  implemented or promised; a bounded explicit manifest expresses the same
  authorized inventory.
- Random or unbounded target generation.

## Implementation notes

- Input lands in [`input/manifest.rs`][cli-manifest]: one declaration per
  physical line (512-byte declaration bound), `#` comments including trailing
  comments, CRLF tolerated, and a shared budget of 1 MiB / 4,096 physical
  lines across every manifest, tightened by `--max-manifest-bytes` /
  `--max-manifest-lines` within those ceilings. All manifests are read before
  policy, resolution, or provider calls, and exactly one `-` stdin consumer is
  admitted across `--targets-file`, `--exclude-file`, `--udp-payload-file`, and
  `--udp-profiles`.
- `scan --list` runs [`Client::plan_targets`][target-plan] through the same
  admission as a live scan and publishes the `target_list` branch of
  `packetcraftr.output/v7`: JSON aggregate, NDJSON `target` records with a
  single `complete` terminal, and text listing each target's scoped address
  and declaration sources plus a DNS warning when resolution ran.
- `Target::ScopedAddress` carries a validated [`Zone`][target-model] on
  unicast `fe80::/10` addresses; zones resolve to exactly one interface id
  via `Resolver::resolve_zone` (numeric index or name, ambiguity and unknown
  interfaces rejected). `SelectedAddress` deduplicates on `(address, resolved
  interface)`, so name/index aliases merge while different interfaces stay
  distinct. Scopes travel through connect sockets (`SocketAddrV6` scope id),
  raw route planning (`route_on` pinned to the resolved interface, route keys
  keyed by scope, mismatched provider answers rejected before sends), and
  endpoint/correlation identity.

## Change map

| Change | Start here |
| --- | --- |
| Target model, zone identity | [`target/model.rs`][target-model] |
| Selection, exclusion, deduplication, provenance | [`target/selection.rs`][target-selection], [`target/admission.rs`][target-admission] |
| Manifest reading and bounds | [`input/bounded.rs`][cli-bounded-input], [`commands/scan/arguments.rs`][scan-args] |
| List mode | [`commands/scan.rs`][scan-command], [`output/scan.rs`][scan-output] |
| Scoped socket endpoints | [`scan/connect/engine.rs`][connect-engine], netio [`interface.rs`][netio-interface] |

## Decisions

Settled at M4 with the recommended positions:

1. **Manifests are line-oriented text.** One declaration per line, `#`
   comments and blank lines ignored, bounded by combined bytes and physical
   lines before parsing — no new document family.
2. **Standard input is an explicit `-` path**, as the capture readers already
   use. One operation admits at most one stdin consumer across include,
   exclude, payload, and profile inputs.
3. **List mode is a mode of `scan` (`--list`)**, so the published plan is the
   selection a scan would execute through the same admission path.
4. **Exclusions stay numeric.** A name-based exclusion would depend on
   resolution the operator has not authorized.
5. **Declared zone text and resolved interface identity travel together** as
   `ResolvedZone`; a zone that does not resolve to exactly one interface is
   rejected, and `%zone` is accepted only on unicast `fe80::/10` addresses for
   this release.
6. **Port selections publish in the list output when [M6][m6] adds them**,
   rather than being designed here.
7. **Scoped output ships in a new `packetcraftr.output/v7` family.**
   Reinterpreting v6 probe/endpoint identity to carry scope would change what
   existing fields mean, and the [compatibility policy][compatibility]
   requires a new family for new enum meanings; v7 adds the `target_list`
   branch and optional `scope` fields mechanically derived from v6, which
   stays frozen.

## Exit criteria

- [x] Numeric list/plan operations send no target or neighbor packets, shown
      with recording providers (`target::plan` tests assert zero provider
      calls for numeric selections; `Call::RouteOn` evidence covers the raw
      scoped path).
- [x] Hostname resolution in list mode requires its opt-in and is reported as
      resolution, not as a network-free operation (`resolution_performed` in
      the `target_list` report; a text warning names DNS traffic).
- [x] Denials, exclusions, malformed input, oversized input, duplicate targets,
      scope ambiguity, and family mismatches each fail or narrow selection
      before active work (`target::plan` and `input::manifest` tests).
- [x] The same declarations produce the same authorized selection whether
      supplied as arguments, a file, or standard input (one ingestion path
      builds `Selection`; `-` is a single stdin consumer across include,
      exclude, payload, and profile inputs).
- [ ] A scoped IPv6 target reaches its socket or route with its scope intact,
      with runtime evidence on each platform that supports it; elsewhere it
      publishes a capability failure. **Done on injected providers** — the
      connect provider records a `SocketAddrV6` carrying the resolved
      `scope_id`, and raw plans route on the resolved interface; native
      platform evidence is still pending, so this criterion stays open.
- [ ] The [gap matrix][matrix] target rows are updated against the reviewed
      revision.

[compatibility]: ../consumer-compatibility.md
[m1]: m01-claims-evidence.md
[m5]: m05-host-discovery.md
[m6]: m06-port-planning-inference.md
[matrix]: nmap-gap-matrix.md
[target-model]: ../../crates/packetcraftr/src/target/model.rs
[target-selection]: ../../crates/packetcraftr/src/target/selection.rs
[target-admission]: ../../crates/packetcraftr/src/target/admission.rs
[connect-engine]: ../../crates/packetcraftr/src/scan/connect/engine.rs
[netio-interface]: ../../crates/packetcraftr-netio/src/interface.rs
[route-plan]: ../../crates/packetcraftr-cli/src/commands/plan.rs
[scan-command]: ../../crates/packetcraftr-cli/src/commands/scan.rs
[scan-args]: ../../crates/packetcraftr-cli/src/commands/scan/arguments.rs
[scan-output]: ../../crates/packetcraftr-cli/src/output/scan.rs
[cli-bounded-input]: ../../crates/packetcraftr-cli/src/input/bounded.rs
[cli-manifest]: ../../crates/packetcraftr-cli/src/input/manifest.rs
[target-plan]: ../../crates/packetcraftr/src/target/plan.rs
[nmap-targets]: https://nmap.org/book/man-target-specification.html
[nmap-discovery]: https://nmap.org/book/man-host-discovery.html
