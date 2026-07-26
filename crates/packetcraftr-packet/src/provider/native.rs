// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;

use packetcraftr_model::{IdentityError, ProviderId, RegistrationOrigin};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::{ProtocolProvider, ProtocolSession, ProviderError, ProviderMatch};
use crate::Packet;
use crate::codec::{
    CodecError, DecodedLayerValue, EncodedLayer, NativeLayerCodec, NativeLayerDecodeContext,
    NativeLayerEncodeContext,
};
use crate::layer::{Layer, ValidatedFieldSet};
use crate::matcher::NativeResponseMatcher;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProviderProtocolKey(Arc<str>);

impl ProviderProtocolKey {
    pub fn new(value: impl AsRef<str>) -> Result<Self, IdentityError> {
        let id = packetcraftr_model::ExtensionId::new(value)?;
        Ok(Self(Arc::from(id.as_str())))
    }

    pub fn from_static(value: &'static str) -> Self {
        let id = packetcraftr_model::ExtensionId::from_static(value);
        Self(Arc::from(id.as_str()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for ProviderProtocolKey {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for ProviderProtocolKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl Serialize for ProviderProtocolKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProviderProtocolKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

#[derive(Clone)]
pub struct NativeProtocolImplementation {
    pub key: ProviderProtocolKey,
    pub codec: Arc<dyn NativeLayerCodec>,
    pub matcher: Option<Arc<dyn NativeResponseMatcher>>,
}

impl fmt::Debug for NativeProtocolImplementation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeProtocolImplementation")
            .field("key", &self.key)
            .field("codec", &self.codec)
            .field("has_matcher", &self.matcher.is_some())
            .finish()
    }
}

impl NativeProtocolImplementation {
    pub fn new<C>(key: ProviderProtocolKey, codec: C) -> Self
    where
        C: NativeLayerCodec + 'static,
    {
        Self {
            key,
            codec: Arc::new(codec),
            matcher: None,
        }
    }

    pub fn with_matcher<M>(mut self, matcher: M) -> Self
    where
        M: NativeResponseMatcher + 'static,
    {
        self.matcher = Some(Arc::new(matcher));
        self
    }
}

#[derive(Clone)]
pub struct NativeProtocolProvider {
    provider_id: ProviderId,
    origin: RegistrationOrigin,
    implementations: Arc<BTreeMap<ProviderProtocolKey, NativeProtocolImplementation>>,
}

impl fmt::Debug for NativeProtocolProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeProtocolProvider")
            .field("provider_id", &self.provider_id)
            .field("origin", &self.origin)
            .field(
                "protocol_keys",
                &self.implementations.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl NativeProtocolProvider {
    pub fn new(
        provider_id: ProviderId,
        origin: RegistrationOrigin,
        implementations: impl IntoIterator<Item = NativeProtocolImplementation>,
    ) -> Result<Self, ProviderError> {
        let mut indexed = BTreeMap::new();
        for implementation in implementations {
            let key = implementation.key.clone();
            if indexed.insert(key.clone(), implementation).is_some() {
                return Err(ProviderError::DuplicateProtocolKey { key });
            }
        }
        Ok(Self {
            provider_id,
            origin,
            implementations: Arc::new(indexed),
        })
    }
}

impl ProtocolProvider for NativeProtocolProvider {
    fn provider_id(&self) -> &ProviderId {
        &self.provider_id
    }

    fn origin(&self) -> &RegistrationOrigin {
        &self.origin
    }

    fn begin_session(&self) -> Result<Box<dyn ProtocolSession>, ProviderError> {
        Ok(Box::new(NativeProtocolSession {
            implementations: Arc::clone(&self.implementations),
        }))
    }
}

#[derive(Clone)]
struct NativeProtocolSession {
    implementations: Arc<BTreeMap<ProviderProtocolKey, NativeProtocolImplementation>>,
}

impl fmt::Debug for NativeProtocolSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NativeProtocolSession")
            .field(
                "protocol_keys",
                &self.implementations.keys().collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl NativeProtocolSession {
    fn implementation(
        &self,
        key: &ProviderProtocolKey,
    ) -> Result<&NativeProtocolImplementation, CodecError> {
        self.implementations
            .get(key)
            .ok_or_else(|| CodecError::Unsupported {
                protocol: packetcraftr_model::ProtocolId::from_static("packetcraftr.provider"),
                message: format!("provider does not own protocol key {key}"),
            })
    }
}

impl ProtocolSession for NativeProtocolSession {
    fn construct(
        &mut self,
        key: &ProviderProtocolKey,
        fields: &ValidatedFieldSet,
    ) -> Result<Box<dyn Layer>, CodecError> {
        self.implementation(key)?.codec.make_layer(fields)
    }

    fn encode(
        &mut self,
        key: &ProviderProtocolKey,
        layer: &dyn Layer,
        payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        self.implementation(key)?
            .codec
            .encode(layer, payload, context)
    }

    fn decode(
        &mut self,
        key: &ProviderProtocolKey,
        input: &[u8],
        context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError> {
        self.implementation(key)?.codec.decode(input, context)
    }

    fn match_response(
        &mut self,
        key: &ProviderProtocolKey,
        request: &Packet,
        response: &Packet,
    ) -> Result<Option<ProviderMatch>, CodecError> {
        let Some(matcher) = self.implementation(key)?.matcher.as_ref() else {
            return Ok(None);
        };
        let result = matcher.matches(request, response);
        let responder = result
            .matched
            .then(|| matcher.responder(request, response))
            .flatten();
        Ok(Some(ProviderMatch { result, responder }))
    }
}
