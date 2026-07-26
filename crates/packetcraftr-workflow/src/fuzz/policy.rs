// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Applies the traffic policy to a complete live fuzz campaign before route,
//! capture, neighbor, or transmission providers are invoked.

use std::net::IpAddr;

use packetcraftr_packet::Packet;
use packetcraftr_policy::{TrafficPolicy, TrafficPolicyError};

use super::FuzzAuthorizer;
use crate::BoundaryError;

pub struct PolicyAuthorizer<'a> {
    policy: &'a TrafficPolicy,
}

impl<'a> PolicyAuthorizer<'a> {
    pub fn new(policy: &'a TrafficPolicy) -> Self {
        Self { policy }
    }
}

impl FuzzAuthorizer for PolicyAuthorizer<'_> {
    fn authorize_operation(
        &mut self,
        packets: &[Packet],
        destination: Option<IpAddr>,
        maximum_wire_bytes: u64,
        requires_malformed_live: bool,
    ) -> Result<(), BoundaryError> {
        self.policy.validate().map_err(BoundaryError::from_error)?;
        let packet_count = packets.len() as u64;
        self.policy
            .authorize_operation(packet_count, maximum_wire_bytes)
            .map_err(BoundaryError::from_error)?;
        if requires_malformed_live && !self.policy.allow_permissive_packets {
            return Err(BoundaryError::from_error(
                TrafficPolicyError::PermissivePacket,
            ));
        }
        if let Some(destination) = destination {
            self.policy
                .authorize_destination(destination)
                .map_err(BoundaryError::from_error)?;
        }
        for packet in packets {
            self.policy
                .authorize_packet_destinations(packet)
                .map_err(BoundaryError::from_error)?;
        }
        Ok(())
    }
}
