# 26: DNS on the client

**What to build:**
- DNS becomes `client.dns(request, sink)`, using the shared admission path. The workflow no longer takes an `Authorizer` or `ExchangeExecutor`, so policy and registry are supplied once.
- DNS-over-TCP becomes a separate capability trait instead of the `TcpExecutor::execute_tcp` default method that fails.
- The DNS-over-TCP socket round trip is renamed from `exchange` to `query`.
- The module takes the fixed roles: `dns/execution.rs` dissolves, `dns::Exchange` keeps its capture-armed meaning, and the private `Operation` that shadows `policy::Operation` is renamed.
- Batch DNS returns a `Report` through the sink instead of `BatchReport`.
- Errors follow the convention: no `#[from] BoundaryError` blanket mapping to `Authorization`, no repeated source text, and typed evidence errors.

Phase 3.

**Blocked by:** 25

**Status:** ready-for-agent

- [ ] The DNS contract tests pass, and the DNS CLI output is unchanged.
- [ ] The in-crate DNS tests (2,322 lines) are kept or replaced at the new interface, with no duplicates.
- [ ] fmt, clippy and the workspace tests pass.
