# M4: Target planning

| Status | Depends on | Unlocks |
| --- | --- | --- |
| Planned | [M1][m1] | [M5][m5] |

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

## Change map

| Change | Start here |
| --- | --- |
| Target model, zone identity | [`target/model.rs`][target-model] |
| Selection, exclusion, deduplication, provenance | [`target/selection.rs`][target-selection], [`target/admission.rs`][target-admission] |
| Manifest reading and bounds | [`input/bounded.rs`][cli-bounded-input], [`commands/scan/arguments.rs`][scan-args] |
| List mode | [`commands/scan.rs`][scan-command], [`output/scan.rs`][scan-output] |
| Scoped socket endpoints | [`scan/connect/engine.rs`][connect-engine], netio [`interface.rs`][netio-interface] |

## Decisions to settle

1. The manifest format (recommended: line-oriented text, one declaration per
   line with comments, because it needs no new document family and is bounded
   by bytes and lines).
2. How standard input is selected (recommended: an explicit `-` path, as the
   capture readers already use).
3. Whether list mode is a mode of `scan` or a separate command (recommended: a
   mode of `scan`, so the listed plan is the plan a scan would execute).
4. Whether exclusions may name hostnames (recommended: keep exclusions numeric,
   because a name-based exclusion depends on resolution the operator has not
   authorized).
5. How a zone is written and stored (recommended: keep the declared text and
   the resolved interface identity together, and reject a zone that does not
   resolve to exactly one interface).
6. Whether list mode also publishes port selections once [M6][m6] exists
   (recommended: yes, extended in M6 rather than designed here).

## Exit criteria

- [ ] Numeric list/plan operations send no target or neighbor packets, shown
      with recording providers.
- [ ] Hostname resolution in list mode requires its opt-in and is reported as
      resolution, not as a network-free operation.
- [ ] Denials, exclusions, malformed input, oversized input, duplicate targets,
      scope ambiguity, and family mismatches each fail or narrow selection
      before active work.
- [ ] The same declarations produce the same authorized selection whether
      supplied as arguments, a file, or standard input.
- [ ] A scoped IPv6 target reaches its socket or route with its scope intact,
      with runtime evidence on each platform that supports it; elsewhere it
      publishes a capability failure.
- [ ] The [gap matrix][matrix] target rows are updated against the reviewed
      revision.

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
[nmap-targets]: https://nmap.org/book/man-target-specification.html
[nmap-discovery]: https://nmap.org/book/man-host-discovery.html
