# ADR 0002: Preserve wire intent and require a second live opt-in

- Status: Accepted
- Date: 2026-07-09

## Context

A packet laboratory must serve two apparently conflicting cases. Most users need correct lengths, checksums, offsets, reserved bits, and layer discriminators. Protocol testing also needs deliberate inconsistencies and malformed encodings. Automatically repairing every value makes negative tests impossible, while accepting every value by default makes accidental malformed transmission too easy.

Decoded packets add another constraint: an untouched capture must rebuild byte-for-byte, including unusual but valid explicit values, while a caller must be able to normalize derived fields after editing.

## Decision

Represent dependent wire fields with:

```text
WireValue<T> = Auto | Exact(T) | Raw(Bytes)
```

- Fresh typed layers use `Auto` for derived values.
- Decoding records exact wire values and retains the complete original bytes.
- `normalize()` resets derived fields to `Auto`.
- `Exact` preserves typed intent and participates in validation.
- `Raw` preserves deliberate byte-level intent and is accepted only where the codec can represent it safely.

The builder has two modes:

- Strict mode validates dependent fields, registered layer bindings, lengths, checksums, and protocol-specific constraints. Contradictions return typed errors.
- Permissive mode emits representable requested values and records structured diagnostics instead of silently repairing them.

`Raw` is not a way to bypass registered layer bindings. When a parent discriminator selects a registered typed child, strict mode rejects a `Raw` child. A discriminator unknown to the registry may retain a `Raw` child so an unmodified capture with an unsupported protocol remains byte-exact. Permissive mode may retain the known-discriminator mismatch, but emits a diagnostic and marks the build as requiring live opt-in.

A permissively built packet is marked as requiring live opt-in. A live operation must receive a separate explicit authorization for malformed transmission; selecting permissive build mode does not satisfy that requirement. Traffic policy can still deny the operation.

Names and addresses have separate authorization boundaries. A live hostname is
validated against the label/name bounds from [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035) and the host syntax update in [RFC 1123](https://www.rfc-editor.org/rfc/rfc1123), then authorized before invoking DNS. Resolution is bounded, and every
distinct selected address is authorized before route planning. Re-resolution
repeats both stages against current policy. The opaque `ResolvedTarget` token
can only be produced by that sequence, so a public address returned after an
initially acceptable name cannot be used implicitly.

The same principle applies to link intent. Explicit Ethernet or VLAN layers force Layer 2. Layer 3 mode with an Ethernet layer is an error. Neighbor-resolution failure cannot change the link mode. Unsupported combinations are typed errors or explicit raw layers, never relabeled payloads. When an IP-root packet explicitly requests Layer 2, the reported Ethernet envelope is inserted into the packet before the preliminary build. Traffic-policy byte accounting therefore covers the complete frame before neighbor discovery, and neighbor materialization may change only fixed-width address fields.

## Consequences

- Correct packet construction remains the safe default.
- Reproducible negative tests are possible without hidden normalization.
- An untouched decoded fixture can be compared and rebuilt exactly.
- API consumers must handle diagnostics even when permissive building succeeds.
- Codecs must define which fields are derived and how strict validation relates parent and child layers.
- Opaque unknown protocol bytes remain round-trippable without letting a known typed discriminator evade its codec's validation.
- Live clients must propagate build provenance and cannot accept a bare byte buffer as evidence that malformed transmission was authorized.
- Live policy limits account for the exact Layer 2 frame rather than only its network-layer payload.
- Hostname-capable workflows cannot use resolution or rebinding to move policy checks after route or network side effects.
- Fuzzing can recalculate all automatic fields except fields selected as mutation targets.

## Alternatives considered

### Always recalculate dependent values

Rejected because it destroys captured wire intent and prevents malformed protocol tests.

### Treat every numeric field as literal

Rejected because callers would need to manually coordinate all dependent values and accidental malformed packets would become common.

### A single `unsafe` or permissive flag

Rejected because build intent and authorization to transmit are different decisions. Two explicit choices make review and traffic policy enforcement possible.

### Silent Layer 2 to Layer 3 fallback

Rejected because it changes the packet the caller intended and can send traffic through a materially different path.
