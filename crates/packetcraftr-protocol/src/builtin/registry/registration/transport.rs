// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_packet::{
    registry::{RegistryBuilder, RegistryError},
    semantics::BuiltinProtocol,
};

use super::bind;

pub(super) fn register(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    for parent in [
        BuiltinProtocol::Udp,
        BuiltinProtocol::Tcp,
        BuiltinProtocol::Sctp,
    ] {
        bind(builder, parent, 0, BuiltinProtocol::Raw, 0)?;
    }
    Ok(())
}
