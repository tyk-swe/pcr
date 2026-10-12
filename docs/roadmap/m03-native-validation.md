# M3: Native validation on three platforms

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | None | Native-runtime [close gates](README.md#close-gates) |

Linux has a disposable privileged namespace lane; reviewed host-local macOS and
Windows routes are implemented but broader acceptance remains incomplete.
[Native validation](../native-validation.md) owns setup, commands, profiles,
and unsupported cases. This milestone adds evidence, not scanner capability.

## Implemented routes

- `.github/workflows/native-platform-review.yml` runs disposable hosted runners
  for an immutable reviewed commit. Checkout identity is verified; reports survive
  failure. Linux uses its separate reviewed namespace route.
- Host-local destinations are literal `127.0.0.1` and scoped IPv6 already assigned
  to the host, preferably loopback, behind a token/platform gate. This isolation
  is not equivalent to Linux namespaces; interface mutation is unavailable.
- Windows uses an existing Npcap installation. No driver download/installation
  is authorized without specific license approval. Unsupported macOS raw IPv6 and
  Windows raw-source restrictions remain capability limits.
- Host-local evidence v3 names platform/profile and every scenario's exercised,
  failed, or unavailable status with a precise reason. Linux netns v1 remains a
  separate release gate. Fake-provider checks and compilation are not native runs.
- All eight authored scenarios are inventoried in each of five feature profiles.
  Disabled capability, absent backend, missing privilege, and inadequate isolation
  remain distinct; an omission is never a pass.

## Security boundaries

Reviewed workflows use no `pull_request_target`, persistent sensitive runners,
or checkout secrets. A maintainer reviews the full commit before dispatch.
Required reviewers/merge protections are administrator-owned; YAML cannot
install them. No scenario contacts an external destination. Linux results never
prove another platform's runtime behavior.

## Recorded evidence

[M4 scoped acceptance](evidence/m04/README.md) at
`8e010a0b9eac118aa13384f0b854111a73d47d76` covers five profiles on Linux,
macOS ARM/Intel, and Windows. Focused host reports intentionally leave seven
other scenarios unexecuted; their scoped pass does not close M3.

M6 first exposed immediate replies arriving before `send()` returned. M5 now
uses the successful exact submission's start, after socket preparation, as the
eligibility boundary. Immediate dual-stack and ARP/NDP fixtures exercise it;
stale/missing monotonic ingress stays ineligible. Neither boundary proves wire
departure, causality, or identity. [M5 evidence](evidence/m05/README.md) does not
substitute for each later milestone's own acceptance.

## Remaining gates

- Execute and retain the complete privileged macOS/Windows inventories across
  supported profiles, including adequate interface isolation.
- Resolve failed/unavailable paths or document the supported capability boundary
  in the [gap matrix](nmap-gap-matrix.md) and validation guide.
- Confirm administrator-owned permission protections for every privileged route.

Compilation, correct typed refusals, and focused host-local successes leave M3
**In progress** until these broader gates are satisfied.
