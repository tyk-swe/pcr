// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_model::{ProviderId, RegistrationOrigin};

use crate::catalog::{
    ProtocolCatalogBuilder, ProtocolCatalogSnapshot, ProtocolRegistration, ProtocolRegistrationSet,
};
use crate::codec::NativeLayerCodec;
use crate::layer::LayerSchema;
use crate::provider::{NativeProtocolImplementation, NativeProtocolProvider, ProviderProtocolKey};

pub(crate) fn native_catalog<C>(schema: Arc<LayerSchema>, codec: C) -> Arc<ProtocolCatalogSnapshot>
where
    C: NativeLayerCodec + 'static,
{
    let provider_id = ProviderId::from_static("packetcraftr.test.native");
    let origin = RegistrationOrigin::Native {
        provider: provider_id.clone(),
    };
    let key = ProviderProtocolKey::new(schema.protocol.as_str())
        .expect("test protocol key must be valid");
    let provider = NativeProtocolProvider::new(
        provider_id.clone(),
        origin.clone(),
        [NativeProtocolImplementation::new(key.clone(), codec)],
    )
    .expect("test provider must be valid");
    let mut set = ProtocolRegistrationSet::new();
    set.register_provider(Arc::new(provider));
    set.register_protocol(ProtocolRegistration::new(schema, provider_id, key, origin));
    let mut builder = ProtocolCatalogBuilder::new();
    builder.registration_set(set);
    Arc::new(builder.build().expect("test catalog must be valid"))
}
