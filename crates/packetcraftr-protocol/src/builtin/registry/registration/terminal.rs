// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_packet::{
    registry::{RegistryBuilder, RegistryError},
    semantics::BuiltinProtocol,
};

use super::bind;

pub(super) fn register(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    bind(
        builder,
        BuiltinProtocol::Arp,
        0,
        BuiltinProtocol::Padding,
        0,
    )
}
