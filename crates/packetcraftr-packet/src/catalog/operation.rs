// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, btree_map};
use std::fmt;
use std::sync::Arc;

use packetcraftr_model::{ProtocolId, ProviderId};
use thiserror::Error;

use super::{ProtocolCatalogSnapshot, ProtocolRegistration};
use crate::Packet;
use crate::codec::{
    CodecError, DecodedLayerValue, EncodedLayer, NativeLayerDecodeContext, NativeLayerEncodeContext,
};
use crate::invariant::{
    decode_payload_end, field_layouts_are_valid, network_envelope_is_valid,
    optional_network_pair_is_valid, protocol_is_owned,
};
use crate::layer::{FieldSetError, Layer, ValidatedFieldSet};
use crate::provider::{ProtocolSession, ProviderError, ProviderMatch};

pub struct ProtocolCatalogOperation {
    snapshot: Arc<ProtocolCatalogSnapshot>,
    sessions: BTreeMap<ProviderId, Box<dyn ProtocolSession>>,
}

impl fmt::Debug for ProtocolCatalogOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProtocolCatalogOperation")
            .field("generation", &self.snapshot.generation())
            .field("catalog_hash", &self.snapshot.catalog_hash())
            .field(
                "started_providers",
                &self.sessions.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ProtocolCatalogOperation {
    pub(crate) fn new(snapshot: Arc<ProtocolCatalogSnapshot>) -> Self {
        Self {
            snapshot,
            sessions: BTreeMap::new(),
        }
    }

    pub fn snapshot(&self) -> &Arc<ProtocolCatalogSnapshot> {
        &self.snapshot
    }

    pub fn started_provider_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn construct_named(
        &mut self,
        name: &str,
        fields: impl IntoIterator<Item = (impl AsRef<str>, crate::field::FieldValue)>,
    ) -> Result<Box<dyn Layer>, ProtocolOperationError> {
        let registration = self
            .snapshot
            .descriptor_named(name)
            .cloned()
            .ok_or_else(|| ProtocolOperationError::UnknownProtocolName {
                name: name.to_owned(),
            })?;
        let fields = ValidatedFieldSet::from_names(Arc::clone(&registration.schema), fields)?;
        self.construct_registered(&registration, &fields)
    }

    pub fn construct(
        &mut self,
        protocol: &ProtocolId,
        fields: &ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, ProtocolOperationError> {
        let registration = self.registration(protocol)?;
        if fields.schema().schema_hash != registration.schema.schema_hash {
            return Err(ProtocolOperationError::SchemaMismatch {
                protocol: protocol.clone(),
            });
        }
        self.construct_registered(&registration, fields)
    }

    pub fn encode(
        &mut self,
        protocol: &ProtocolId,
        layer: &dyn Layer,
        payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, ProtocolOperationError> {
        let registration = self.registration(protocol)?;
        self.validate_layer(&registration, layer)?;
        if !optional_network_pair_is_valid(
            context.build_context.source,
            context.build_context.destination,
        ) {
            return Err(ProtocolOperationError::InvalidNetworkEnvelope {
                protocol: protocol.clone(),
            });
        }
        let encoded = self
            .session(&registration.provider)?
            .encode(&registration.provider_key, layer, payload, context)
            .map_err(|source| ProtocolOperationError::Codec {
                protocol: protocol.clone(),
                source,
            })?;
        self.validate_layer(&registration, encoded.materialized.as_ref())?;
        if !field_layouts_are_valid(
            encoded.materialized.as_ref(),
            &encoded.fields,
            encoded.prefix.len(),
        ) {
            return Err(ProtocolOperationError::InvalidLayout {
                protocol: protocol.clone(),
            });
        }
        Ok(encoded)
    }

    pub fn decode(
        &mut self,
        protocol: &ProtocolId,
        input: &[u8],
        context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, ProtocolOperationError> {
        let registration = self.registration(protocol)?;
        if context
            .network
            .is_some_and(|network| !network_envelope_is_valid(network))
        {
            return Err(ProtocolOperationError::InvalidNetworkEnvelope {
                protocol: protocol.clone(),
            });
        }
        let decoded = self
            .session(&registration.provider)?
            .decode(&registration.provider_key, input, context)
            .map_err(|source| ProtocolOperationError::Codec {
                protocol: protocol.clone(),
                source,
            })?;
        if !registration.accepts_decoded_protocol(decoded.layer.protocol_id()) {
            return Err(ProtocolOperationError::AcceptedDecode {
                requested: protocol.clone(),
                actual: decoded.layer.protocol_id().clone(),
            });
        }
        let decoded_registration = self.registration(decoded.layer.protocol_id())?;
        self.validate_layer(&decoded_registration, decoded.layer.as_ref())?;
        if decode_payload_end(
            input.len(),
            decoded.consumed,
            decoded.payload_offset,
            decoded.payload_len,
            decoded.stop,
        )
        .is_none()
        {
            return Err(ProtocolOperationError::InvalidCursor {
                protocol: protocol.clone(),
            });
        }
        if !field_layouts_are_valid(decoded.layer.as_ref(), &decoded.fields, decoded.consumed) {
            return Err(ProtocolOperationError::InvalidLayout {
                protocol: protocol.clone(),
            });
        }
        if decoded
            .network
            .is_some_and(|network| !network_envelope_is_valid(network))
        {
            return Err(ProtocolOperationError::InvalidNetworkEnvelope {
                protocol: protocol.clone(),
            });
        }
        Ok(decoded)
    }

    pub fn match_response(
        &mut self,
        protocol: &ProtocolId,
        request: &Packet,
        response: &Packet,
    ) -> Result<Option<ProviderMatch>, ProtocolOperationError> {
        let registration = self.registration(protocol)?;
        if !registration.matcher {
            return Ok(None);
        }
        self.session(&registration.provider)?
            .match_response(&registration.provider_key, request, response)
            .map_err(|source| ProtocolOperationError::Codec {
                protocol: protocol.clone(),
                source,
            })
    }

    fn construct_registered(
        &mut self,
        registration: &ProtocolRegistration,
        fields: &ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, ProtocolOperationError> {
        let layer = self
            .session(&registration.provider)?
            .construct(&registration.provider_key, fields)
            .map_err(|source| ProtocolOperationError::Codec {
                protocol: registration.protocol.clone(),
                source,
            })?;
        self.validate_layer(registration, layer.as_ref())?;
        Ok(layer)
    }

    fn validate_layer(
        &self,
        registration: &ProtocolRegistration,
        layer: &dyn Layer,
    ) -> Result<(), ProtocolOperationError> {
        if !protocol_is_owned(&registration.protocol, layer.protocol_id()) {
            return Err(ProtocolOperationError::ProtocolOwnership {
                expected: registration.protocol.clone(),
                actual: layer.protocol_id().clone(),
            });
        }
        if layer.schema().schema_hash != registration.schema.schema_hash {
            return Err(ProtocolOperationError::SchemaMismatch {
                protocol: registration.protocol.clone(),
            });
        }
        layer.validate_required_fields().map_err(|source| {
            ProtocolOperationError::InvalidLayer {
                protocol: registration.protocol.clone(),
                source,
            }
        })?;
        Ok(())
    }

    fn registration(
        &self,
        protocol: &ProtocolId,
    ) -> Result<ProtocolRegistration, ProtocolOperationError> {
        self.snapshot.descriptor(protocol).cloned().ok_or_else(|| {
            ProtocolOperationError::UnknownProtocol {
                protocol: protocol.clone(),
            }
        })
    }

    fn session(
        &mut self,
        provider: &ProviderId,
    ) -> Result<&mut Box<dyn ProtocolSession>, ProtocolOperationError> {
        match self.sessions.entry(provider.clone()) {
            btree_map::Entry::Occupied(entry) => Ok(entry.into_mut()),
            btree_map::Entry::Vacant(entry) => {
                let factory = self.snapshot.provider(provider).cloned().ok_or_else(|| {
                    ProtocolOperationError::UnknownProvider {
                        provider: provider.clone(),
                    }
                })?;
                let session =
                    factory
                        .begin_session()
                        .map_err(|source| ProtocolOperationError::Provider {
                            provider: provider.clone(),
                            source,
                        })?;
                Ok(entry.insert(session))
            }
        }
    }
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ProtocolOperationError {
    #[error("catalog has no protocol named {name}")]
    UnknownProtocolName { name: String },
    #[error("catalog has no protocol {protocol}")]
    UnknownProtocol { protocol: ProtocolId },
    #[error("catalog has no provider {provider}")]
    UnknownProvider { provider: ProviderId },
    #[error("could not start provider {provider}: {source}")]
    Provider {
        provider: ProviderId,
        #[source]
        source: ProviderError,
    },
    #[error("provider operation for {protocol} failed: {source}")]
    Codec {
        protocol: ProtocolId,
        #[source]
        source: CodecError,
    },
    #[error("protocol {protocol} was constructed with a different schema")]
    SchemaMismatch { protocol: ProtocolId },
    #[error("provider returned protocol {actual}; expected owned protocol {expected}")]
    ProtocolOwnership {
        expected: ProtocolId,
        actual: ProtocolId,
    },
    #[error("provider decode for {requested} returned unaccepted protocol {actual}")]
    AcceptedDecode {
        requested: ProtocolId,
        actual: ProtocolId,
    },
    #[error("provider returned a layer for {protocol} that violates its schema: {source}")]
    InvalidLayer {
        protocol: ProtocolId,
        #[source]
        source: crate::layer::FieldError,
    },
    #[error("provider returned invalid cursor or payload ranges for {protocol}")]
    InvalidCursor { protocol: ProtocolId },
    #[error("provider returned invalid field layouts for {protocol}")]
    InvalidLayout { protocol: ProtocolId },
    #[error("provider returned a mixed-family network envelope for {protocol}")]
    InvalidNetworkEnvelope { protocol: ProtocolId },
    #[error(transparent)]
    Fields(#[from] FieldSetError),
}
