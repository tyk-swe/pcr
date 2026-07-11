# Release feedback and support boundaries

`0.2.0` publishes the Rust API, CLI grammar and exit classes, packet and output
schemas, exact portable wire bytes, and GitHub Release artifact contract frozen
at Beta. Report a suspected regression through the
[GitHub issue tracker](https://github.com/tyk-swe/pcr/issues/new) with:

- the release version, source commit from `RELEASE-METADATA.toml`, operating
  system/target, Cargo feature set, and installation path;
- the smallest non-sensitive packet, capture, command, or downstream-code
  reproducer; and
- the expected contract, observed result, exit code, and complete diagnostics.

Do not attach sensitive production captures. Report vulnerabilities through
the private process in [`SECURITY.md`](../SECURITY.md).

Maintainers triage confirmed stable regressions through the security or issue
process as appropriate. An incompatible frozen-contract regression,
qualified-capability defect, artifact/version/source mismatch, or
unbounded-resource regression requires an explicit fix and supported Release;
compatible additions and work outside the published v0.2 scope may be
scheduled separately.

The Beta originally required privileged Linux, macOS, and Windows live-I/O
runs, cross-platform parity, and the final security/resource/package audit.
On 2026-07-11 the release owner explicitly removed real Windows/Npcap live I/O
from the qualified 0.2.0 scope because its dedicated runner was unavailable.
That path is documented as an unqualified preview rather than silently deferred
or represented as passing; the other exact-lineage qualification gates remain.
