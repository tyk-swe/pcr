// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Well-known application discriminator bindings.

use packetcraftr_packet::registry::{RegistryBuilder, RegistryError};
use packetcraftr_packet::semantics::BuiltinProtocol;

use super::bind;

pub(super) fn register(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    bind(builder, BuiltinProtocol::Udp, 53, BuiltinProtocol::Dns, 100)
}
