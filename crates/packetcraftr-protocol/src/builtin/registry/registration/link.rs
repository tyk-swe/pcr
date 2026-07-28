// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_packet::{
    registry::{RegistryBuilder, RegistryError},
    semantics::BuiltinProtocol,
};

use super::{bind, bind_link_children};
use crate::{link::LLC_FRAME_DISCRIMINATOR, support::BUILTIN_CAPTURE_ROOTS};

pub(super) fn register(builder: &mut RegistryBuilder) -> Result<(), RegistryError> {
    for root in BUILTIN_CAPTURE_ROOTS {
        builder.bind_link_type(root.link_type, root.protocol)?;
    }

    bind_link_children(builder, BuiltinProtocol::Ethernet)?;
    bind_link_children(builder, BuiltinProtocol::Vlan)?;
    bind_link_children(builder, BuiltinProtocol::Vlan8021ad)?;
    for parent in [
        BuiltinProtocol::Ethernet,
        BuiltinProtocol::Vlan,
        BuiltinProtocol::Vlan8021ad,
    ] {
        bind(
            builder,
            parent,
            LLC_FRAME_DISCRIMINATOR,
            BuiltinProtocol::Llc,
            100,
        )?;
    }
    bind(
        builder,
        BuiltinProtocol::Llc,
        0xaaaa,
        BuiltinProtocol::Snap,
        100,
    )?;
    bind(builder, BuiltinProtocol::Llc, 0, BuiltinProtocol::Raw, -100)?;
    bind_link_children(builder, BuiltinProtocol::Snap)?;
    for parent in [BuiltinProtocol::LinuxSll, BuiltinProtocol::LinuxSll2] {
        bind_link_children(builder, parent)?;
    }
    for parent in [BuiltinProtocol::BsdNull, BuiltinProtocol::BsdLoop] {
        bind(builder, parent, 4, BuiltinProtocol::Ipv4, 100)?;
        bind(builder, parent, 6, BuiltinProtocol::Ipv6, 100)?;
        bind(builder, parent, 0, BuiltinProtocol::Raw, -100)?;
    }
    Ok(())
}
