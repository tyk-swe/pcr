// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::{build::BuiltPacket, layer::Padding, protocol::BuiltinProtocol};

use crate::Error;

pub(super) fn validate_mtu(built: &BuiltPacket, mtu: u32) -> Result<(), Error> {
    let network_layer = built.packet.iter().enumerate().find_map(|(index, layer)| {
        BuiltinProtocol::of(layer)
            .is_some_and(BuiltinProtocol::is_ip)
            .then_some(index)
    });
    let network_length = network_layer.and_then(|index| {
        let start = built.layout.layer(index)?.range.start;
        let outside_network = built
            .packet
            .iter()
            .rev()
            .take_while(|layer| layer.is::<Padding>())
            .filter_map(|layer| layer.downcast_ref::<Padding>())
            .filter(|padding| padding.excluded_from(index))
            .try_fold(0_usize, |total, padding| {
                total.checked_add(padding.bytes.len())
            })?;
        built
            .bytes
            .len()
            .checked_sub(outside_network)?
            .checked_sub(start)
    });
    if let Some(actual) = network_length
        && actual > usize::try_from(mtu).unwrap_or(usize::MAX)
    {
        return Err(Error::PacketExceedsMtu { actual, mtu });
    }
    Ok(())
}
