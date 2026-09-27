// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Recipe fields filled with bytes from outside the recipe.

use bytes::Bytes;

use crate::error::{Classification, Classified, Kind, Source};
use crate::field::{self, FieldValue};

/// A `LAYER.FIELD` recipe field that receives bytes from outside the
/// recipe: `LAYER` is a zero-based layer index and `FIELD` a field path,
/// read case-insensitively.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    layer: usize,
    field: String,
}

impl std::str::FromStr for Target {
    type Err = Error;

    fn from_str(selector: &str) -> Result<Self, Error> {
        let (layer, field) = selector.trim().split_once('.').ok_or(Error::Syntax)?;
        let layer = layer.parse().map_err(|_| Error::Syntax)?;
        let field = field.trim().to_ascii_lowercase();
        if field.is_empty() {
            return Err(Error::Syntax);
        }
        Ok(Self { layer, field })
    }
}

impl Target {
    /// The zero-based layer index.
    pub fn layer(&self) -> usize {
        self.layer
    }

    /// The field path, lowercased.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Fills the target field of `packet` with the bytes `load` returns.
    ///
    /// The field must exist, be bytes-typed, and be empty in the recipe;
    /// `load` runs only after those checks pass, so a bad target never reads
    /// its source.
    pub fn inject<E: From<Error>>(
        &self,
        packet: &mut crate::packet::Packet,
        load: impl FnOnce() -> Result<Bytes, E>,
    ) -> Result<(), E> {
        let layers = packet.len();
        let layer = packet.layer_mut(self.layer).ok_or(Error::LayerOutOfRange {
            layer: self.layer,
            layers,
        })?;
        let unknown = || Error::UnknownField {
            layer: self.layer,
            field: self.field.clone(),
        };
        let path = self.field.parse::<field::Path>().map_err(|_| unknown())?;
        let FieldValue::Bytes(current) = layer.field_path(&path).ok_or_else(unknown)? else {
            return Err(Error::NotBytes {
                layer: self.layer,
                field: self.field.clone(),
            }
            .into());
        };
        if !current.is_empty() {
            return Err(Error::Occupied {
                layer: self.layer,
                field: self.field.clone(),
            }
            .into());
        }
        let bytes = load()?;
        layer
            .set_field_path(&path, FieldValue::Bytes(bytes))
            .map_err(|source| {
                Error::Set {
                    layer: self.layer,
                    field: self.field.clone(),
                    source: Source::new(source),
                }
                .into()
            })
    }
}

/// Why a payload target cannot receive bytes.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The target is not `LAYER.FIELD` with a zero-based layer index.
    #[error("payload target requires LAYER.FIELD with a zero-based layer index")]
    Syntax,
    #[error("payload layer index {layer} is outside the recipe's {layers} layers")]
    LayerOutOfRange { layer: usize, layers: usize },
    #[error("payload field {field} is unknown on layer {layer}")]
    UnknownField { layer: usize, field: String },
    #[error("payload field {field} on layer {layer} is not bytes-typed")]
    NotBytes { layer: usize, field: String },
    #[error("payload field {field} on layer {layer} already holds recipe bytes")]
    Occupied { layer: usize, field: String },
    /// The layer refused the bytes.
    #[error("could not set payload field {field} on layer {layer}")]
    Set {
        layer: usize,
        field: String,
        #[source]
        source: Source,
    },
}

impl Classified for Error {
    fn classification(&self) -> Classification {
        Classification::new("cli.error", Kind::Usage, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_targets_parse_a_zero_based_layer_and_a_lowercased_field() {
        let target: Target = " 2.BYTES ".parse().expect("valid target");
        assert_eq!((target.layer(), target.field()), (2, "bytes"));
        for invalid in ["2", "x.bytes", "-1.bytes", "2 .bytes", "2. "] {
            assert!(
                matches!(invalid.parse::<Target>(), Err(Error::Syntax)),
                "{invalid:?}"
            );
        }
    }
}
