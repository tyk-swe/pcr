//! Byte-level packet layouts.

mod model;

pub use model::{
    ByteRange as Range, FieldLayout as Field, LayerLayout as Layer, PacketLayout as Packet,
};
pub(crate) use model::{ByteRange, FieldLayout, LayerLayout, PacketLayout};
