// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

//! Portable packet model, reflection, registry, building, and bounded dissection.
//!
//! This module has no dependency on an async runtime or operating-system packet I/O.

mod build;
mod capture;
mod diagnostic;
mod dissect;
mod document;
mod expression;
mod layer;
mod layout;
mod packet;
mod registry;
mod template;
mod value;

pub use build::{
    BuildContext, BuildError, BuildMode, BuildOptions, Builder, BuiltPacket, DEFAULT_MAX_LAYERS,
    DEFAULT_MAX_PACKET_SIZE,
};
pub use capture::{CaptureDirection, CaptureRecordError, CapturedFrame, LinkType};
pub use diagnostic::{Diagnostic, DiagnosticSeverity};
pub use dissect::{DecodeError, DecodeOptions, DecodedPacket, Dissector};
pub use document::{
    DocumentError, DocumentFormat, LayerDocument, PacketDocument, DEFAULT_MAX_DOCUMENT_BYTES,
    DEFAULT_MAX_DOCUMENT_NESTING, PACKET_DOCUMENT_SCHEMA_V1,
};
pub use expression::{
    decode_hex, parse_packet_expression, ExpressionError, ExpressionOptions,
    DEFAULT_MAX_EXPRESSION_BYTES,
};
pub use layer::{
    FieldError, FieldSchema, Layer, LayerSchema, MalformedLayer, Padding, ProtocolId, Raw,
};
pub use layout::{ByteRange, FieldLayout, LayerLayout, PacketLayout};
pub use packet::{Packet, PacketError};
pub use registry::{
    CodecError, DecodedLayerValue, Discriminator, EncodedLayer, LayerCodec, LayerDecodeContext,
    LayerEncodeContext, MatchResult, NetworkEnvelope, ProtocolModule, ProtocolRegistry,
    RegistryBuilder, RegistryError, ResponseMatcher,
};
pub use template::{
    PacketTemplate, PacketTemplateIter, PacketTransform, TemplateError, TemplateValues,
    DEFAULT_MAX_TEMPLATE_PACKETS,
};
pub use value::{FieldKind, FieldValue, WireValue};
