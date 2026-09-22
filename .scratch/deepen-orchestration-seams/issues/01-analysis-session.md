# 01 — `analysis::Session`: collapse the collector lifecycle

Status: ready-for-agent

Part of `.scratch/deepen-orchestration-seams/spec.md` (Problem 1, Solution 1).

Introduce a `Session` module in `packetcraftr-core`'s `analysis` area that
owns preparation (including `filter::Requirements → Plan` narrowing), the
observe/finish loop over a capture reader, IP-event forwarding, the
trailing drain, and the empty-selector verdict. Rewrite the `http`,
`dns_read`, `expert`, `follow`, and `tls` commands to supply only a
collector and an event sink.

Unit tests beside the module drive scripted frames and fake collectors.
Process-level contract tests must pass unchanged.
