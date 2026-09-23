# 04: Batch evidence moves into the probe runner (serial scan and traceroute)

**What to build:** The probe runner owns batch-evidence processing: the permit check, diagnostic recording and publishing order, response selection through the shared selector, retention of winning responses, undecoded retention with its diagnostic fallback, and the per-probe emit order. The workflow hook narrows from execute/validate/process to a classifier: classify one response against a sent probe, rank it, give the tie-break responder, build the probe's evidence (timeout or response), map retained frames and diagnostics to events, and report whether the batch is terminal. The executor is passed to the runner. Serial scan and traceroute migrate to it. Scan uses the shared batch type, and its single-probe batch type, its batch-plan impl and the slice-of-one adaptations go away. See the spec's "Batch evidence" section.

**Blocked by:** 01

**Status:** resolved

- [x] The scan and traceroute engines contain only workflow-specific classification and evidence shapes. Their copied process-batch, classify, retain, undecoded-retention and diagnostic-publishing routines are gone.
- [x] Tests beside the probe runner drive batches with a fake executor and a fake classifier. They assert the permit-mismatch rejection, diagnostics published before each probe's event, the tie-break rule (rank → responder → latency → bytes), retention limits with the undecoded fallback diagnostic, and a terminal batch ending the operation. The old fake lifecycle, which reimplemented validation, is replaced.
- [x] The scan and traceroute tests that both checked event collection preserving stats, diagnostics and evidence limits become one runner test.
- [x] Scan, traceroute and probe contract tests pass.
- [x] fmt, clippy and the workspace tests pass.
