//! Versioned packet documents.

mod model;

pub(crate) use model::PacketDocument;
pub use model::{
    DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_DOCUMENT_NESTING, DocumentError as Error,
    DocumentFormat as Format, LayerDocument as Layer, MAX_DOCUMENT_NESTING,
    PACKET_DOCUMENT_SCHEMA_V1, PacketDocument as Packet,
};
