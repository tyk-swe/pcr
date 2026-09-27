# HTTP-T01: Add bounded HTTP header transactions in core

Status: ready-for-agent
Blocked by: BASE-01
Size: medium
Spec: [correlation, timing, core API, and HT01–HT15](../spec.md)

## What to build

1. Read the existing HTTP queue/framing transitions before editing. Add the
   private `analysis/http/transaction.rs` owner and the public types/method/event
   specified by the feature spec. Extend existing pending-request state;
   retain one correlator for message links and transactions.
2. Pass the current physical `FrameRecord` marker through HTTP's private
   delivery path. Record boundaries only when bytes are consumed/head parsing
   succeeds. Leave shared application/DNS delivery contracts unchanged.
3. Implement informational accumulation, final pairing, each orphan response,
   and exactly-once unanswered retirement. Preserve enqueue-before-body-framing
   semantics and existing parser-disable/connection-generation behavior.
4. Apply the specified additional cumulative charges before state changes.
   Implement signed intervals without floating point or source-set inference.
   Disabled transactions retain no additional pending metadata. Close
   configuration on the first observe attempt and enforce HT15.
5. Update exhaustive matches in library consumers, examples, CLI, and existing
   HTTP fuzz targets for the new Event variant. The CLI may reject an unexpected
   transaction as an invariant until HTTP-T02 enables collection; never discard
   a transaction from an enabled collector silently.

## Acceptance and validation

- [ ] HT01–HT13 core behavior is covered in `http_analysis_contracts.rs`, with
  small owner unit tests only for arithmetic/state boundaries that public
  regressions do not cover.
- [ ] Public tests exercise fragment completion and gap filling through the
  actual analysis pipeline, not only handcrafted availability markers.
- [ ] Existing HTTP messages, request associations, summaries, and default
  collector event order remain unchanged when the option is disabled.
- [ ] Pending retirement never duplicates rows on generation replacement/EOF.
- [ ] Allocation/resource failure retains typed sources and classified limits.

```sh
cargo test --locked -p packetcraftr-core --test http_analysis_contracts --test http_framing_contracts
cargo test --locked -p packetcraftr-core --lib analysis::http
cargo test --locked -p packetcraftr-cli --no-default-features --test http_contracts
```

Record any Rust source-compatibility impact in Unreleased; document the added
event for exhaustive-match callers. No parser/protocol rules are added here.

## Comments

The timing spec and ADR 0005 settle the tempting but incorrect alternative of
using the minimum source-frame timestamp as first-byte time.
