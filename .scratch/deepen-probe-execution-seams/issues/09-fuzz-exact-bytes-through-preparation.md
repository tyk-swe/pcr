# 09: Fuzz checks its executor's bytes through the preparation module

**What to build:** The staged preparation module from ticket 07 exposes a deterministic "exact bytes for this packet on this route" operation that uses the same materialization rules. Fuzz's expected-live-build check uses it instead of re-deriving route materialization, and the hand-built materialization fixture in fuzz's tests is deleted. See the spec's "Staged preparation" section and user stories 25–26.

**Blocked by:** 02, 07

**Status:** ready-for-agent

- [ ] Fuzz no longer re-derives materialization.
- [ ] A test shows the exact-bytes operation matches what was transmitted for the same packet and route.
- [ ] Fuzz tests stop hand-building route materialization steps.
- [ ] The fuzz contract tests pass.
- [ ] fmt, clippy and the workspace tests pass.
