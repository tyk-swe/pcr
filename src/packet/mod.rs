// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

//! Runtime-neutral packet model, construction, decoding, and extension contracts.

#[path = "build.rs"]
mod build_impl;
#[path = "dissect.rs"]
mod decode_impl;
#[path = "diagnostic.rs"]
mod diagnostic_impl;
#[path = "document.rs"]
mod document_impl;
#[path = "expression.rs"]
mod expression_impl;
#[path = "layer.rs"]
mod layer_impl;
#[path = "layout.rs"]
mod layout_impl;
#[path = "packet.rs"]
mod packet_impl;
#[path = "registry.rs"]
mod registry_impl;
#[path = "template.rs"]
mod template_impl;
#[path = "value.rs"]
mod value_impl;

pub use packet_impl::{Packet, PacketError as Error};

pub mod layer {
    //! Packet layer models and reflection.

    pub use super::layer_impl::{
        Layer, LayerSchema as Schema, MalformedLayer as Malformed, Padding, ProtocolId as Id, Raw,
    };

    pub(crate) use super::layer_impl::{
        FieldError, FieldSchema, LayerSchema, MalformedLayer, ProtocolId,
    };
}

pub mod field {
    //! Reflective field schemas and values.

    pub use super::layer_impl::{FieldError as Error, FieldSchema as Schema};
    pub use super::value_impl::{FieldKind as Kind, FieldValue as Value, WireValue as Wire};

    pub(crate) use super::value_impl::{FieldKind, FieldValue, WireValue};
}

pub mod build {
    //! Exact packet construction.

    pub use super::build_impl::{
        BuildContext as Context, BuildError as Error, BuildMode as Mode, BuildOptions as Options,
        Builder, BuiltPacket as Result, DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE,
    };

    pub(crate) use super::build_impl::{
        BuildContext, BuildError, BuildMode, BuildOptions, BuiltPacket,
    };
}

pub mod decode {
    //! Bounded packet decoding.

    pub use super::decode_impl::{
        DecodeError as Error, DecodeOptions as Options, DecodedPacket as Result,
        Dissector as Decoder,
    };

    pub(crate) use super::decode_impl::{DecodeError, DecodeOptions, DecodedPacket, Dissector};
}

pub mod layout {
    //! Byte-level packet layouts.

    pub use super::layout_impl::{
        ByteRange as Range, FieldLayout as Field, LayerLayout as Layer, PacketLayout as Packet,
    };

    pub(crate) use super::layout_impl::{ByteRange, FieldLayout, LayerLayout, PacketLayout};
}

pub mod document {
    //! Versioned packet documents.

    pub use super::document_impl::{
        DocumentError as Error, DocumentFormat as Format, LayerDocument as Layer,
        PacketDocument as Packet, DEFAULT_MAX_DOCUMENT_BYTES, DEFAULT_MAX_DOCUMENT_NESTING,
        MAX_DOCUMENT_NESTING, PACKET_DOCUMENT_SCHEMA_V1,
    };

    pub(crate) use super::document_impl::{
        DocumentError, DocumentFormat, LayerDocument, PacketDocument,
    };
}

pub mod expression {
    //! Compact packet expressions.

    pub use super::expression_impl::{
        decode_hex, parse_packet_expression as parse, ExpressionError as Error,
        ExpressionOptions as Options, DEFAULT_MAX_EXPRESSION_BYTES, MAX_EXPRESSION_NESTING,
    };

    pub(crate) use super::expression_impl::{
        parse_packet_expression, ExpressionError, ExpressionOptions,
    };
}

pub mod template {
    //! Bounded packet templates.

    pub use super::template_impl::{
        PacketTemplate as Template, PacketTemplateIter as Iter, TemplateError as Error,
        TemplateValues as Values, DEFAULT_MAX_TEMPLATE_PACKETS,
    };

    pub(crate) use super::template_impl::{
        PacketTemplate, PacketTemplateIter, TemplateError, TemplateValues,
    };
}

pub mod diagnostic {
    //! Structured diagnostics produced by build and decode operations.

    pub use super::diagnostic_impl::{Diagnostic, DiagnosticSeverity as Severity};

    pub(crate) use super::diagnostic_impl::DiagnosticSeverity;
}

pub mod codec {
    //! Extension contract for packet codecs.

    pub use super::registry_impl::{
        CodecError as Error, DecodedLayerValue as Decoded, EncodedLayer as Encoded,
        LayerCodec as Codec, LayerDecodeContext as DecodeContext,
        LayerEncodeContext as EncodeContext, NetworkEnvelope,
    };
}

pub mod registry {
    //! Deterministic protocol registration.

    pub use super::registry_impl::{
        Discriminator, ProtocolModule as Module, ProtocolRegistry as Registry,
        RegistryBuilder as Builder, RegistryError as Error,
    };

    #[allow(unused_imports)]
    pub(crate) use super::registry_impl::{
        CodecError, DecodedLayerValue, EncodedLayer, LayerCodec, LayerDecodeContext,
        LayerEncodeContext, MatchResult, ProtocolModule, ProtocolRegistry, RegistryBuilder,
        RegistryError, ResponseMatcher,
    };
}

pub mod matcher {
    //! Response-correlation extension contracts.

    pub use super::registry_impl::{MatchResult as Result, ResponseMatcher as Matcher};
}

/// Flat implementation vocabulary used only while composing the library's domains.
/// It is deliberately unavailable to downstream crates.
#[allow(unused_imports)]
pub(crate) mod internal {
    pub(crate) use super::build::{
        BuildContext, BuildError, BuildMode, BuildOptions, Builder, BuiltPacket,
        DEFAULT_MAX_LAYERS, DEFAULT_MAX_PACKET_SIZE,
    };
    pub(crate) use super::codec::{
        Codec as LayerCodec, DecodeContext as LayerDecodeContext, Decoded as DecodedLayerValue,
        EncodeContext as LayerEncodeContext, Encoded as EncodedLayer, Error as CodecError,
        NetworkEnvelope,
    };
    pub(crate) use super::decode::{DecodeError, DecodeOptions, DecodedPacket, Dissector};
    pub(crate) use super::diagnostic::{Diagnostic, DiagnosticSeverity};
    pub(crate) use super::document::{
        DocumentError, DocumentFormat, LayerDocument, PacketDocument, DEFAULT_MAX_DOCUMENT_BYTES,
        DEFAULT_MAX_DOCUMENT_NESTING, MAX_DOCUMENT_NESTING, PACKET_DOCUMENT_SCHEMA_V1,
    };
    pub(crate) use super::expression::{
        decode_hex, parse_packet_expression, ExpressionError, ExpressionOptions,
        DEFAULT_MAX_EXPRESSION_BYTES, MAX_EXPRESSION_NESTING,
    };
    pub(crate) use super::field::{FieldKind, FieldValue, WireValue};
    pub(crate) use super::layer::{
        FieldError, FieldSchema, Layer, LayerSchema, MalformedLayer, Padding, ProtocolId, Raw,
    };
    pub(crate) use super::layout::{ByteRange, FieldLayout, LayerLayout, PacketLayout};
    pub(crate) use super::matcher::{Matcher as ResponseMatcher, Result as MatchResult};
    pub(crate) use super::registry::{
        Builder as RegistryBuilder, Discriminator, Error as RegistryError,
        Module as ProtocolModule, Registry as ProtocolRegistry,
    };
    pub(crate) use super::template::{
        PacketTemplate, PacketTemplateIter, TemplateError, TemplateValues,
        DEFAULT_MAX_TEMPLATE_PACKETS,
    };
    pub(crate) use super::{Error as PacketError, Packet};
}
