//! Deterministic protocol registration.

pub(crate) mod core;

pub(crate) use super::codec::{CodecError, LayerDecodeContext, LayerEncodeContext};
pub use core::{
    Discriminator, ProtocolModule as Module, ProtocolRegistry as Registry,
    RegistryBuilder as Builder, RegistryError as Error,
};
pub(crate) use core::{ProtocolModule, ProtocolRegistry, RegistryBuilder, RegistryError};
