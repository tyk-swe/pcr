# Protocol extension architecture

PacketcraftR's packet kernel is runtime-neutral. It knows about protocol
providers and short-lived sessions, but it does not depend on Wasmtime, a
plugin host, or a guest ABI. Trusted native codecs and a future Wasm adapter use
the same catalog and operation lifecycle.

## Schemas and layers

`LayerSchema` owns its display name, normalized aliases, ordered field
descriptors, schema version, and SHA-256 schema identity. Every `FieldSchema`
has a deliberately assigned `FieldId`; field order and a generated hash are
never used as substitutes for that stable identity. Schema construction rejects
invalid or duplicate IDs, canonical names, and aliases, and validates bounded
numeric and length constraints.

Built-in Rust layers retain their concrete types and can still be obtained with
`Packet::get::<T>()`. `Layer::field_by_id` is the primary object-safe reflection
path, while `field` and `set_field` resolve canonicalized names through the
schema.

`DynamicLayer` is the host-owned representation for a protocol without a native
Rust model. It stores an `Arc<LayerSchema>` and one optional value per schema
slot. Construction validates unknown and duplicate fields, kinds, constraints,
and required values before the layer can enter a packet:

```rust
use std::sync::Arc;

use packetcraftr::packet::{
    field::{FieldKind, FieldValue},
    layer::{
        DynamicLayer, FieldConstraints, FieldId, FieldSchema, Layer, LayerSchema,
        ProtocolId,
    },
};

fn example() -> Result<(), Box<dyn std::error::Error>> {
    let schema = Arc::new(LayerSchema::new(
        ProtocolId::new("example.counter")?,
        "Example counter",
        ["counter"],
        1,
        [FieldSchema::new(
            FieldId::new("value")?,
            "value",
            ["v"],
            FieldKind::Unsigned,
            true,
            false,
            "Counter value",
            FieldConstraints::unsigned(0, 65_535),
        )?],
    )?);
    let layer = DynamicLayer::from_named(
        schema,
        [("v", FieldValue::Unsigned(7))],
    )?;
    assert_eq!(
        layer.field_by_id(&FieldId::new("value")?),
        Some(FieldValue::Unsigned(7)),
    );
    Ok(())
}
```

Dynamic layers participate in packet cloning, documents, expressions,
templates, building, dissection, output conversion, and field-aware fuzzing
through the same `Layer` contract.

## Providers and operation scope

`ProtocolProvider` is an immutable factory with a validated `ProviderId` and
`RegistrationOrigin`. `begin_session` creates a non-shared
`ProtocolSession`. A provider can own several protocol IDs, each addressed by a
provider-local `ProviderProtocolKey`.

Every packet transaction creates a `ProtocolCatalogOperation` pinned to one
`Arc<ProtocolCatalogSnapshot>`. The operation starts a provider session lazily
on first use, reuses it for all protocols from that provider during the
transaction, and drops it at the end. A later build, decode, construction, or
matching transaction receives a new session. Sessions are mutable and are not
required to be `Send`, so a future Wasm adapter can own one Store and component
instance without sharing either globally or concurrently.

`NativeProtocolProvider` adapts trusted `NativeLayerCodec` and
`NativeResponseMatcher` implementations. Codec contexts contain only the
packet facts and parent-local bindings resolved by the host; they cannot inspect
the complete catalog. Decode results return host-neutral discriminators, which
the packet engine resolves after validating protocol ownership, accepted decode
protocols, schemas, required fields, cursor and payload ranges, layouts, packet
and layer limits, and network-envelope families.

## Catalog construction and bindings

A `NativeProtocolModule` returns a `ProtocolRegistrationSet`.
`ProtocolCatalogBuilder` canonicalizes all input and produces an immutable
snapshot containing descriptors, owned schemas, selected provider factories,
aliases, capture roots, decode and reverse bindings, matcher availability, and
the provenance of every selected registration. Equivalent selected
registrations produce the same `CatalogHash` regardless of insertion order;
the separately assigned generation does not alter that content identity.

Bindings have no numeric priority:

- an exact `(parent, discriminator)` selects one decode child;
- `BindingDirection::Canonical` also creates the sole reverse discriminator for
  its `(parent, child)` pair;
- `BindingDirection::DecodeOnly` creates no reverse encoding choice;
- multiple decode spellings for one child must therefore mark the additional
  spellings decode-only; and
- raw or malformed fallback behavior is an explicit fallback registration.

Conflicting third-party claims fail deterministically. A built-in registration
remains selected when an unselected third-party claim conflicts with it.
Replacing that protocol, alias, capture root, binding, or fallback requires a
`ProtocolCatalogPolicy` selection naming the exact `RegistrationOrigin`.
`packetcraftr.*` and every built-in canonical protocol ID remain protected even
when the built-in module is not otherwise present.

The removed mutable `ProtocolRegistry`, `RegistryBuilder`, priority-bearing
bindings, `LayerCodec`, and `ResponseMatcher` APIs have no compatibility
facades. Consumers should pass `Arc<ProtocolCatalogSnapshot>` to packet,
client, and workflow operations and register trusted native implementations
through providers.
