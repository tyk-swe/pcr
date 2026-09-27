# SPLIT-01: Implement raw-record capture part planning and writing

Status: resolved (1333cbaf; all listed tests green)
Blocked by: BASE-01
Size: medium
Spec: [fidelity, core API, algorithm, limits, SP01–SP09/SP16–SP17](../spec.md)

## What to build

1. Add `capture_file::split` with the exact plan/write API and private state
   described in the spec. Reuse capture-file raw record and section-patching
   internals and rewind at planning start. Expose the existing interruption
   check only within capture_file for replay/sink boundaries.
2. Read/validate the whole source, bound metadata before retaining it, build
   anchored metadata and part descriptions, and preflight exact output bytes.
   Include initial header in metadata accounting. Compute source SHA-256.
3. Rewind once and implement sequential packet copying with cached metadata
   replay, checked output charging, sink backpressure, and digest comparison.
   Preserve arbitrary validated metadata bytes and source block kinds.
4. Add typed split errors with the specified classifications and original
   capture/sink sources. A failed sink cannot receive later callbacks.
5. Add public behavior regressions in `capture_split_contracts.rs`; reuse
   established fidelity fixture helpers where useful, without source-layout
   assertions or exposing raw cache internals to integration tests.

## Acceptance and validation

- [x] SP01–SP05, the uncompressed cases of SP06, SP07, SP09, SP16 and replay
  cancellation in SP17 pass at the core boundary, including a changed source
  with the same size/counts, empty capture, and metadata-run coalescence.
  Compressed-input SP06 and encoded-output SP08 belong to SPLIT-02.
- [x] Outputs equal existing `capture_file::select` bytes for every range;
  combined raw packet records reproduce the source sequence.
- [x] Limits are preflighted before first sink begin when knowable; write-time
  counters/digest revalidate the planned source.
- [x] Metadata replay uses no whole-input-per-part scan, packet accumulation,
  dissection, filesystem path, or native provider.

```sh
cargo test --locked -p packetcraftr-core --test capture_split_contracts --test pcap_fidelity_contracts --test pcap_rewrite_contracts --test capture_limit_contracts
```

Extend the existing capture transformation fuzz target with a tightly bounded
split/selection equivalence case; compile it in BASE-02. Memory/performance
tests should observe bounded retained state and reads, not host-specific timing.

## Comments

The public plan report lets CLI preflight every filename before generating
staging; exposing the raw metadata cache is unnecessary.
