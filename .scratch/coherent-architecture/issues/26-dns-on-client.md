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

**Status:** resolved

- [x] The DNS contract tests pass, and the DNS CLI output is unchanged.
- [x] The in-crate DNS tests (2,322 lines) are kept or replaced at the new interface, with no duplicates.
- [x] fmt, clippy and the workspace tests pass.

## Comments

- Batch events are `dns::batch::Event { question, event }` (a question-tagged
  `dns::Event`) instead of `Event::{Query, Question}`: a question-end event
  published after the shared deadline expired would fail the publication and
  turn a completed question into an error.
- `dns::Request` gains `route` and `collection` (serde-skipped live settings);
  a batch's questions must also share them.
- `dns::Probe`, `classify_response`, and `ResponseClassification` stay public:
  the `fuzz/` dns_message target classifies responses offline with them. The
  rest of the executor seam (`Exchange`, `Execution`, TCP query and evidence)
  is crate-private.
- The private engine struct is `Retries`; `PreparedOperation` keeps its name
  (it no longer shadows `policy::Operation`, which is imported directly).
- Only `Query` and `TcpExecution` repeated source text; their messages change
  (changelog "Changed"). `Authorization`/`Execution`/`Output` keep
  `{source}` because their `causes` delegate to the `BoundaryError` snapshot,
  as in scan and send.
- The IT that scripted a TCP `Unsupported` failure mid-batch moved in-crate
  (`batch_totals_include_traffic_from_questions_that_later_fail`); a client
  cannot fail one attempt with a route override. The other DNS ITs run on a
  client over fake providers.
