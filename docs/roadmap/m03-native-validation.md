# M3: Native validation on three platforms

| Status | Depends on | Unlocks |
| --- | --- | --- |
| In progress | None | Native-runtime [close gates](README.md#close-gates) |

Linux has a disposable privileged namespace lane; reviewed host-local macOS and
Windows routes exist, while broader cross-platform acceptance remains open.
[Native validation](../native-validation.md) owns setup, commands, profiles,
and unsupported cases.

## Implemented routes

- `.github/workflows/native-platform-review.yml` runs disposable hosted runners
  for an immutable reviewed commit; Linux uses its separate namespace route.
- Host-local destinations are literal `127.0.0.1` and already-assigned scoped IPv6
  behind a token/platform gate, without interface mutation or driver installation.
- Host-local evidence v3 records each of eight scenarios across five profiles as
  exercised, failed, or unavailable with a reason code; Linux netns v1 is a
  separate release gate.
- Reviewed workflows avoid `pull_request_target`, persistent sensitive runners,
  checkout secrets, and external destinations.

## Recorded evidence

- [M4 scoped acceptance](evidence/m04/README.md) (`8e010a0b9eac118aa13384f0b854111a73d47d76`)
  covers five profiles on Linux, macOS ARM/Intel, and Windows for `scoped_ipv6_targets`
  (leaving the other seven M3 scenarios unselected on host-local runners) plus
  all eight Linux isolated scenarios.
- [M5 Linux acceptance](evidence/m05/README.md) (`e7f3e2efa7b47ba2ffa7e2818dbcc4d53eaef9e3`)
  verifies immediate-reply eligibility from `transmit::Timing::freshness_marker()`.

## Remaining gates

- Execute and retain complete privileged macOS/Windows inventories across
  supported profiles, including adequate interface isolation.
- Resolve failed/unavailable paths or document the supported capability boundary
  in the [gap matrix](nmap-gap-matrix.md) and validation guide.
- Confirm administrator-owned permission protections for every privileged route.
