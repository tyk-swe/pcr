# HTTP-B01: Deliver selected HTTP entity bytes to a bounded sink

Status: ready-for-agent
Blocked by: HTTP-T01
Size: medium
Spec: [core API, byte meaning, resources, HB01–HB17](../spec.md)

## What to build

1. Add `BodyDecoder::consume_with` and `ConsumeError<E>` in the current body
   parser. Share the state machine with existing count/discard consumption.
   Emit borrowed entity spans only after their bound has been checked.
2. Add the selected synchronous `BodySink` capability to `analysis::http`.
   Keep callback invocation inside parsing; propagate sink failures as
   `application::Error::Output`, with original classification and causes.
3. Add the minimal collector lifetime/private target state; preserve ordinary
   construction, transaction mode, and all unselected body behavior. Update
   public examples/fuzz consumers affected by the API surface.
4. Keep protocol framing behavior unchanged. The new seam exposes the parser's
   existing entity decisions; it does not add an independent HTTP decoder.

## Acceptance and validation

- [ ] HB01–HB06, HB08, HB12–HB13, HB15, HB17 hold at the core API boundary.
- [ ] Every-byte segmentation fixtures distinguish entity bytes from chunk
  syntax/trailers and pipelined data; include binary content and clean FIN.
- [ ] Callback failure prevents later invocations in that analysis run.
- [ ] Beyond-limit bytes never reach the callback, even in a large input slice.
- [ ] Default `consume`/collector behavior and transaction evidence pass their
  existing regressions without retaining body bytes.

```sh
cargo test --locked -p packetcraftr-core --test http_framing_contracts --test http_analysis_contracts
cargo test --locked -p packetcraftr-core --lib protocol::application::http
cargo test --locked -p packetcraftr-core --lib analysis::http
```

Put protocol behavior in `http_framing_contracts.rs` and selected-collector
behavior in `http_analysis_contracts.rs`; avoid duplicating the same cases at
both layers. Document the callback's terminal-error contract in Rustdoc.

## Comments

No CLI paths, files, hashing, or serialized body chunk events belong in core.
