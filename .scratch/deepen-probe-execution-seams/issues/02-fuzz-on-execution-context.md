# 02: Fuzz campaign paces and executes through the execution context

**What to build:** The fuzz campaign's pacing (cases per second) and its case execution go through the execution context from ticket 01, with a fuzz error adapter. Fuzz's private execution-phase struct stops being a test surface. See the spec's "Execution context" section and user stories 10–17.

**Blocked by:** 01

**Status:** resolved

- [x] Fuzz computes its own delay and hands it to the context. The context owns the pacing and step order, including the canonical pacing order and checking the permit immediately.
- [x] Fuzz's own pacing and execute-case plumbing is gone. Fuzz keeps only fuzz semantics: case generation, evidence and classification.
- [x] Fuzz's run tests that mirrored the runner's pacing tests are deleted, since the execution context's suite covers them. Any remaining fuzz tests drive the campaign through its public or engine interface without building a private phase struct field by field.
- [x] The fuzz cancellation contract tests still pass.
- [x] `[Unreleased]` records the canonical pacing order for fuzz: after a sleep, the deadline and cancellation are checked before a clock failure is reported.
- [x] fmt, clippy and the workspace tests pass.
