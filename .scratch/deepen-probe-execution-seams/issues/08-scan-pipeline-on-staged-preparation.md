# 08: Scan pipeline prepares through the staged preparation module

**What to build:** The scan pipeline's preparation uses the all-before-discovery mode of the staged preparation module from ticket 07. Packets are rebuilt at send time under the prepared-bytes limit, and the module checks that each rebuild matches the admitted cost, so the pipeline's bounded-memory rebuild path can't skip that check. See the spec's "Staged preparation" section and user stories 20 and 24.

**Blocked by:** 05, 07

**Status:** resolved

- [x] The pipeline's copied plan → authorize → budget → materialize → final-check → transmit chain is gone. What stays in the pipeline is pipeline-specific: the prepared-description memory charge, capture-interface grouping and batching.
- [x] A test through the client or pipeline shows a rebuild that doesn't match the admitted cost is rejected.
- [x] The scan pipeline contract tests pass.
- [x] fmt, clippy and the workspace tests pass.
