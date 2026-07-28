// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_packet::registry::{RegistryBuilder, RegistryError};

pub(super) fn register(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    crate::builtin::filter::register_filter_fields(builder)
}
