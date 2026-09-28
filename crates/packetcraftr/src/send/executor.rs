// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Error;
use crate::{
    Client, clock::Clock, evidence::SentPacket, preparation::Streaming, providers::PacketProviders,
};
use packetcraftr_core::packet::Packet;
use packetcraftr_netio::deadline::MAX_WAIT;
use std::time::Duration;

pub(super) fn send<P: PacketProviders, K: Clock>(
    client: &Client<P, K>,
    stream: &mut Streaming<'_, P, K>,
    expanded: Result<Packet, packetcraftr_core::template::Error>,
    delay: Option<Duration>,
) -> Result<SentPacket, Error> {
    stream.check()?;
    let prepared = stream.prepare(expanded.map_err(crate::Error::from)?)?;
    if let Some(delay) = delay {
        stream.check()?;
        client
            .clock
            .sleep(delay, &client.deadline(MAX_WAIT))
            .map_err(|source| Error::Clock {
                source: Box::new(source),
            })?;
    }
    Ok(stream.transmit(prepared)?)
}
