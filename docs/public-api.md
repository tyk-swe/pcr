# Stable Rust API contract

The v0.2 beta surface is the `packetcraftr` façade. Applications may use its
top-level reexports or the intentional `packetcraftr::{core, protocols, io,
session, tools, client, output, error}` module paths. The synchronized
`packetcraftr-*` component packages are implementation boundaries for release
assembly, are not published independently, and are not compatibility entry
points.

Provider contracts are owned by `packetcraftr::io` and reexported at the crate
root. The alpha-only `packetcraftr::client::{PacketIo, CaptureProvider, ...}`
aliases were removed at the freeze; import those names from `packetcraftr` or
`packetcraftr::io`.

## Ownership, mutation, and concurrency

- `Packet`, packet layers, templates, and workflow options are caller-owned
  values. Mutation requires `&mut`; building and dissection return owned result
  values and do not mutate a global packet model.
- `RegistryBuilder` is the mutable composition phase. `ProtocolRegistry` is
  immutable after `build()` and is normally shared through `Arc`.
- `Layer` and `LayerCodec` are `Send + Sync`. I/O providers are `Send + Sync`;
  an owned `CaptureSession` is `Send` and uses `&mut self` for readiness,
  receive, and shutdown so one owner controls its lifecycle.
- Native handles and wrapper-specific values stay behind the private I/O
  platform boundary. Public provider traits use only standard-library and
  PacketcraftR-owned values.

The component ownership is intentional: `core` owns packet/schema/registry and
build/dissect contracts; `protocols` owns built-in codecs; `io` owns capture,
route, neighbor, and send providers; `session` owns bounded reassembly; and the
façade owns policy, clients, reusable workflows, output, and CLI composition.

## Reflective schema invariant

`FieldSchema::required` means that `Layer::field(name)` must return `Some`
after a codec has applied defaults. It does not mean that an expression or
packet document must spell the field. Codec factories may supply a default,
but constructed, build-materialized, and decoded layers must expose every
required field. Public factory, builder, and dissector boundaries enforce this
through `Layer::validate_required_fields()` and return a typed
`FieldError::MissingRequired` cause when an external codec violates it.

## Results and errors

Portable build/dissect calls return `BuiltPacket` and `DecodedPacket`; route
planning returns `PlannedRoute` and explicit neighbor materialization returns
`MaterializedRoute`; live send/exchange calls return `SendReport` and
`ExchangeResult`. These values retain packet, exact-byte, layout, diagnostic,
route, capture, and cleanup evidence appropriate to the operation.

Public error enums that can grow are `#[non_exhaustive]`. Match the variants
you can recover from and keep a wildcard arm. Errors crossing workflow or CLI
boundaries implement `ClassifiedError`. `ErrorClassification` has:

- a stable machine `code`;
- a `FailureKind` that determines the frozen CLI exit-code family;
- a `FailureCategory` that distinguishes validation, capability, policy,
  timeout, runtime I/O, cleanup, and invariant handling; and
- optional operator remediation.

`ErrorClassification` is non-exhaustive; construct custom classifications with
`ErrorClassification::new` and, when needed, `with_category`. Aggregate
operation-and-cleanup variants classify as `Cleanup` while retaining both
causes.

`CaptureStatistics` is the authoritative capture-completeness API. It exposes
bounded-queue overflow observations, total drops, and the receiver-reported
drop subset. `evidence_completeness()` derives `Complete` or `Incomplete`, and
`evidence_loss_error()` distinguishes queue overflow from other receiver loss.
Diagnostics may explain a lossy policy, but callers never need to parse a log
message to decide whether evidence is complete.

## Bounds and safety

Every parser, template, reassembly stage, capture queue, retained evidence set,
retry loop, and live workflow has explicit limits. Defaults are finite; public
`validate` methods reject zero, inconsistent, overflowing, or over-maximum
configurations before side effects. Increasing a limit is an allocation and
traffic decision owned by the caller.

There are no public unsafe preconditions. Fallible capture constructors verify
captured/original lengths, checked `Layer2Frame`/`Layer3Frame` constructors
enforce link-mode ownership, and native adapters validate OS data before
turning it into public values. Live use still requires an authorized target,
the selected native Cargo capability, its trusted runtime dependency, and the
minimum operating-system privilege described in the platform matrix.

## Portable composition

The ordinary portable path needs no native provider:

```rust
use packetcraftr::{
    default_registry, BuildContext, BuildOptions, Builder, Packet, Raw,
};
use std::sync::Arc;

let registry = Arc::new(default_registry()?);
let mut packet = Packet::new();
packet.push(Raw::new(vec![0xde, 0xad, 0xbe, 0xef]));
let built = Builder::new(registry).build(
    packet,
    BuildContext::default(),
    BuildOptions::default(),
)?;
assert_eq!(built.bytes.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
# Ok::<(), Box<dyn std::error::Error>>(())
```

An application can package external codecs as a `ProtocolModule` using only
public contracts. Each codec supplied below implements the public
`LayerCodec` trait; a complete compile-tested codec is also maintained in
`tests/external_protocol.rs`.

```rust
use packetcraftr::{
    BuiltinProtocols, LayerCodec, ProtocolModule, ProtocolRegistry,
    RegistryBuilder, RegistryError,
};
use std::sync::Arc;

struct ApplicationProtocols {
    codecs: Vec<Arc<dyn LayerCodec>>,
}

impl ProtocolModule for ApplicationProtocols {
    fn register(&self, builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
        for codec in &self.codecs {
            builder.register_codec_arc(Arc::clone(codec))?;
        }
        Ok(())
    }
}

let application = ApplicationProtocols { codecs: Vec::new() };
let mut builder = ProtocolRegistry::builder();
builder.module(&BuiltinProtocols)?.module(&application)?;
let registry = builder.build()?;
assert!(registry.protocol_named("ethernet").is_some());
# Ok::<(), RegistryError>(())
```

Injected providers likewise use no platform internals:

```rust
use packetcraftr::{InterfaceInfo, InterfaceProvider, LiveIoError};

struct ApplicationInterfaces;

impl InterfaceProvider for ApplicationInterfaces {
    fn interfaces(&self) -> Result<Vec<InterfaceInfo>, LiveIoError> {
        Ok(Vec::new())
    }
}

assert!(ApplicationInterfaces.interfaces()?.is_empty());
# Ok::<(), LiveIoError>(())
```

A system provider crosses an explicit live boundary. This example performs
interface discovery only; send and capture additionally require their native
features, policy authorization, finite limits, and platform privileges.

```no_run
use packetcraftr::{InterfaceProvider, SystemInterfaceProvider};

let interfaces = SystemInterfaceProvider.interfaces()?;
for interface in interfaces {
    println!("{}", interface.id.name);
}
# Ok::<(), packetcraftr::LiveIoError>(())
```

## Compatibility review

`api/packetcraftr-v0.2-beta.txt` records façade item paths, declarations, and
inherent/trait member signatures generated by the pinned rustdoc toolchain.
CI rebuilds and compares that baseline. Updating it requires a compatibility
review and a changelog entry carrying the new baseline digest. Additive changes
still need review; removals, renames, field/variant changes, signature changes,
trait-bound changes, and ownership-path changes are compatibility changes.

After beta, make a public change only when the v0.2 compatibility policy allows
it, update migration guidance when callers must act, and regenerate the
baseline deliberately. Implementation details, private platform adapters, and
unpublished component-package paths are outside this façade promise.
