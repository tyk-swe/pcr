# 05: Pipelined scan goes through the same batch-evidence processing and tie-break

**What to build:** The pipelined scan path sends its completed-probe events through the batch-evidence processing that ticket 04 put in the probe runner, so permit checks, diagnostic order and retention match serial scan. The pipeline executor's in-flight best-so-far choice uses the serial selector's candidate ordering. Sanctioned change: pipelined ties no longer go to the first arrival; they use rank → responder → latency → bytes. See the spec's "Batch evidence" section and user stories 3–5.

**Blocked by:** 04

**Status:** ready-for-agent

- [ ] The pipeline's own ranking (the strict greater-than on `rank()*4 + profile`) is gone. One ordering is shared with the serial selector.
- [ ] A runner-level or scan-pipeline test shows a tie that used to go to the first arrival in pipelined mode now picks the same winner as serial mode.
- [ ] The scan pipeline contract tests still pass as the outer net, updated only where they pin the sanctioned tie-break.
- [ ] `[Unreleased]` records the single tie-break rule.
- [ ] fmt, clippy and the workspace tests pass.
