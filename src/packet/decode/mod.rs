//! Bounded packet decoding.

mod engine;

pub use engine::{
    DecodeError as Error, DecodeOptions as Options, DecodedPacket as Result, Dissector as Decoder,
};
pub(crate) use engine::{DecodeError, DecodeOptions, DecodedPacket, Dissector};
