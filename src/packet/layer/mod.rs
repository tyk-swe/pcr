//! Packet layer models and reflection.

pub(crate) mod model;
mod reflection;

pub(crate) use model::{FieldError, FieldSchema, LayerSchema, MalformedLayer, ProtocolId};
pub use model::{
    Layer, LayerSchema as Schema, MalformedLayer as Malformed, Padding, ProtocolId as Id, Raw,
};
pub(crate) use reflection::{reflect_get, reflect_set, reflective_layer};
