// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use thiserror::Error;

use crate::error::{Classification, Classified, Kind};

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("packet document has {actual} bytes, exceeding limit {limit}")]
    SizeLimit { actual: usize, limit: usize },
    #[error("could not parse {format} packet document: {message}")]
    Parse {
        format: &'static str,
        message: String,
    },
    #[error("schema: got `{actual}`, expected `{expected}`; specify schema: {expected}")]
    Schema {
        actual: String,
        expected: &'static str,
    },
    #[error(
        "schema: got `{got}`, expected `packetcraftr.packet/v2`; specify schema: packetcraftr.packet/v2"
    )]
    UnknownSchema { got: String },
    #[error(
        "layer#{layer}: got {detail}, expected a single-key map {{<protocol>: {{<fields>}}}}; specify each layer as a map with one protocol key"
    )]
    LayerShape {
        layer: usize,
        keys: Vec<String>,
        detail: String,
    },
    #[error("packet document has more than {limit} layers")]
    LayerLimit { limit: usize },
    #[error("packet document field nesting exceeds configured limit {limit}")]
    NestingLimit { limit: usize },
    #[error("packet document limit {field}={value} exceeds stable maximum {maximum}")]
    InvalidLimit {
        field: &'static str,
        value: usize,
        maximum: usize,
    },
    #[error(
        "layer#{layer}: got unknown protocol `{protocol}`, expected a supported protocol name; check protocol spelling or run `packetcraftr protocols`"
    )]
    UnknownProtocol { layer: usize, protocol: String },
    #[error(
        "{path}: got unknown field `{field}`, expected a valid field name; check field spelling against protocol schema"
    )]
    UnknownField { path: String, field: String },
    #[error(
        "{path}: got duplicate field alias `{alias}` for canonical `{canonical}`, expected a single field entry; remove one of the duplicate fields"
    )]
    DuplicateField {
        path: String,
        canonical: String,
        alias: String,
    },
    #[error("{path}: got `{got}`, expected {expected}; provide a value matching the field schema")]
    ValueForm {
        path: String,
        got: String,
        expected: String,
    },
    #[error(
        "{path}: got `{got}`, expected an unsigned integer at most {max}; use a value in range"
    )]
    OutOfRange { path: String, got: String, max: u64 },
    #[error("{path}: got `auto`, expected a literal value; `auto` is only valid on derived fields")]
    AutoNotDerived { path: String },
    #[error(
        "{path}: got missing required field, expected a value; provide a value for this required field"
    )]
    MissingRequired { path: String },
    #[error(
        "{path}: got decode-only protocol `{protocol}`, expected a constructible protocol; decode-only protocols cannot be built from documents"
    )]
    DecodeOnly { path: String, protocol: String },
    #[error("invalid {protocol} layer at index {layer}: {source}")]
    Layer {
        layer: usize,
        protocol: String,
        #[source]
        source: crate::codec::Error,
    },
    #[error("could not serialize {format} packet document: {message}")]
    Serialize {
        format: &'static str,
        message: String,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::SizeLimit { .. }
            | Self::LayerLimit { .. }
            | Self::NestingLimit { .. }
            | Self::InvalidLimit { .. } => Classification::new(
                "document.limit",
                Kind::Request,
                Some("adjust resource limits"),
            ),
            Self::Parse { .. } => {
                Classification::new("document.parse", Kind::Request, Some("fix document syntax"))
            }
            Self::Schema { .. } | Self::UnknownSchema { .. } => Classification::new(
                "document.unknown_schema",
                Kind::Request,
                Some("specify schema: packetcraftr.packet/v2"),
            ),
            Self::LayerShape { .. } => Classification::new(
                "document.layer_shape",
                Kind::Request,
                Some("format each layer as a single-key map"),
            ),
            Self::UnknownProtocol { .. } => Classification::new(
                "document.unknown_protocol",
                Kind::Request,
                Some("use a supported protocol identifier"),
            ),
            Self::UnknownField { .. } => Classification::new(
                "document.unknown_field",
                Kind::Request,
                Some("use declared protocol field names"),
            ),
            Self::DuplicateField { .. } => Classification::new(
                "document.duplicate_field",
                Kind::Request,
                Some("specify each field at most once"),
            ),
            Self::ValueForm { .. } | Self::OutOfRange { .. } => Classification::new(
                "document.value_form",
                Kind::Request,
                Some("match the field's declared data kind"),
            ),
            Self::AutoNotDerived { .. } => Classification::new(
                "document.auto_not_derived",
                Kind::Request,
                Some("provide an explicit literal value"),
            ),
            Self::MissingRequired { .. } => Classification::new(
                "document.missing_required",
                Kind::Request,
                Some("supply all required layer fields"),
            ),
            Self::DecodeOnly { .. } => Classification::new(
                "document.decode_only",
                Kind::Request,
                Some("replace decode-only layers with raw"),
            ),
            Self::Layer { .. } => Classification::new(
                "document.layer",
                Kind::Request,
                Some("correct invalid layer field configuration"),
            ),
            Self::Serialize { .. } => Classification::new(
                "document.serialize",
                Kind::Request,
                Some("ensure document values are serializable"),
            ),
        }
    }
}

/// Structured warning emitted when a v1 packet document is processed.
pub fn deprecated_schema_diagnostic(target: &str) -> crate::diagnostic::Diagnostic {
    let target = if target.is_empty() { "<path>" } else { target };
    crate::diagnostic::Diagnostic::warning(
        "document.deprecated_schema",
        format!(
            "packetcraftr.packet/v1 is deprecated; run `packetcraftr convert {target}` to rewrite it as packetcraftr.packet/v2"
        ),
    )
}
