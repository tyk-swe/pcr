//! Extension contract for packet codecs.

mod contract;

pub(crate) use contract::{
    CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext,
};
pub use contract::{
    CodecError as Error, DecodedLayerValue as Decoded, EncodedLayer as Encoded,
    LayerCodec as Codec, LayerDecodeContext as DecodeContext, LayerEncodeContext as EncodeContext,
    NetworkEnvelope,
};
