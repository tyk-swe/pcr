# Centralize ordered stream generations

Status: open
Blocked by: 03
Spec: ../spec.md §§ Implementation Decisions 3; Testing Decisions

Pipeline derives per-frame ordered, generation-tagged stream events from reuse detection without changing public per-frame reassembly events or conversation indices. Collectors declare needs; migrate HTTP/DNS source tracker, TLS, follow dedup and expert eviction handling to generation view. Recording session tests cover reuse (including same-frame data), expiry of other flow, reset and clean close ordering. Shrink duplicate collector reuse tests. Work from merged ticket 03 session changes.
