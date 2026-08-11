// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::Packet;

pub(super) fn structurally_eq(left_packet: &Packet, right_packet: &Packet) -> bool {
    if left_packet.len() != right_packet.len() {
        return false;
    }
    left_packet
        .iter()
        .zip(right_packet.iter())
        .all(|(left, right)| {
            if left.protocol_id() != right.protocol_id() {
                return false;
            }
            if left.schema() != right.schema() {
                return false;
            }
            left.schema()
                .fields
                .iter()
                .all(|field| left.field(field.name) == right.field(field.name))
        })
}
