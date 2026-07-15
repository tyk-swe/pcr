//! Versioned packet documents.

mod model;

pub(crate) use model::PacketDocument;
pub use model::{
    DEFAULT_MAX_AST_NODES, DEFAULT_MAX_COLLECTION_ITEMS, DEFAULT_MAX_DOCUMENT_BYTES,
    DEFAULT_MAX_DOCUMENT_LAYERS, DEFAULT_MAX_DOCUMENT_NESTING, DEFAULT_MAX_FIELDS_PER_LAYER,
    DEFAULT_MAX_KEY_BYTES, DEFAULT_MAX_OWNED_SCALAR_BYTES, DEFAULT_MAX_TOTAL_FIELDS,
    DocumentError as Error, DocumentFormat as Format, LayerDocument as Layer, Limits,
    MAX_DOCUMENT_NESTING, PACKET_DOCUMENT_SCHEMA_V1, PacketDocument as Packet,
};
