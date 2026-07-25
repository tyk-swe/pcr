// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Post-transmission send-report and MTU validation.

use bytes::Bytes;

use crate::net::{Error as LiveIoError, transmit::IoSendReport};
use crate::packet::{build::BuiltPacket, layer::Padding, semantics::BuiltinProtocol};

use super::send::ClientError;

pub(super) fn validate_send_report(
    expected: &Bytes,
    report: &IoSendReport,
) -> Result<(), LiveIoError> {
    if report.bytes_sent != expected.len() {
        return Err(LiveIoError::PartialSend {
            expected: expected.len(),
            actual: report.bytes_sent,
        });
    }
    if let Some(wire_bytes) = &report.wire_bytes {
        if wire_bytes.len() != report.bytes_sent {
            return Err(LiveIoError::InvalidSendReport {
                bytes_sent: report.bytes_sent,
                wire_bytes: wire_bytes.len(),
            });
        }
        if wire_bytes != expected {
            return Err(LiveIoError::InvalidSendEvidence {
                message: "wire_bytes differ from the exact submitted packet".to_owned(),
            });
        }
    }
    Ok(())
}

pub(super) fn validate_mtu(built: &BuiltPacket, mtu: u32) -> Result<(), ClientError> {
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
            .take_while(|layer| layer.as_any().is::<Padding>())
            .filter_map(|layer| layer.as_any().downcast_ref::<Padding>())
            .filter(|padding| {
                padding
                    .outside_layer
                    .is_none_or(|outside_layer| index >= outside_layer)
            })
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
        && actual > mtu as usize
    {
        return Err(ClientError::PacketExceedsMtu { actual, mtu });
    }
    Ok(())
}
