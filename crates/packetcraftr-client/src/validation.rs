// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Post-transmission send-report and MTU validation.

use bytes::Bytes;

use packetcraftr_net::{Error as LiveIoError, transmit::IoSendReport};
use packetcraftr_packet::{build::BuiltPacket, layer::Padding, semantics::BuiltinProtocol};

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
    if report.wire_bytes.len() != report.bytes_sent {
        return Err(LiveIoError::InvalidSendReport {
            bytes_sent: report.bytes_sent,
            wire_bytes: report.wire_bytes.len(),
        });
    }
    if report.wire_bytes != *expected {
        return Err(LiveIoError::InvalidSendEvidence {
            message: "wire_bytes differ from the exact submitted packet".to_owned(),
        });
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use packetcraftr_packet::{
        Packet,
        build::{Builder, Context, Options},
        field::WireValue,
        layer::{Padding, Raw},
    };
    use packetcraftr_protocol::{link::Ethernet, network::Ipv4, transport::Udp};

    use super::*;

    #[test]
    fn send_report_requires_exact_count_length_and_wire_bytes() {
        let expected = Bytes::from_static(&[1, 2, 3]);
        assert!(
            validate_send_report(
                &expected,
                &IoSendReport {
                    bytes_sent: 3,
                    wire_bytes: expected.clone(),
                }
            )
            .is_ok()
        );
        assert!(matches!(
            validate_send_report(
                &expected,
                &IoSendReport {
                    bytes_sent: 2,
                    wire_bytes: Bytes::from_static(&[1, 2]),
                }
            ),
            Err(LiveIoError::PartialSend {
                expected: 3,
                actual: 2
            })
        ));
        assert!(matches!(
            validate_send_report(
                &expected,
                &IoSendReport {
                    bytes_sent: 3,
                    wire_bytes: Bytes::from_static(&[1, 2]),
                }
            ),
            Err(LiveIoError::InvalidSendReport {
                bytes_sent: 3,
                wire_bytes: 2
            })
        ));
        assert!(matches!(
            validate_send_report(
                &expected,
                &IoSendReport {
                    bytes_sent: 3,
                    wire_bytes: Bytes::from_static(&[3, 2, 1]),
                }
            ),
            Err(LiveIoError::InvalidSendEvidence { .. })
        ));
    }

    fn build(packet: Packet) -> BuiltPacket {
        Builder::new(Arc::new(
            packetcraftr_protocol::builtin::registry().expect("built-in registry"),
        ))
        .build(packet, Context::default(), Options::default())
        .expect("fixture packet builds")
    }

    #[test]
    fn mtu_validation_counts_network_bytes_and_excludes_trailing_link_padding() {
        let mut packet = Packet::new();
        packet.push(Ethernet::default());
        packet.push(Ipv4 {
            source: Ipv4Addr::new(192, 0, 2, 1),
            destination: Ipv4Addr::new(192, 0, 2, 2),
            ..Ipv4::default()
        });
        packet.push(Udp {
            source_port: 12_345,
            destination_port: 9_999,
            ..Udp::default()
        });
        packet.push(Raw::new(vec![1_u8, 2, 3, 4]));
        packet.push(Padding::new(vec![0_u8; 12]));
        let built = build(packet);

        assert_eq!(built.bytes.len(), 58);
        assert!(validate_mtu(&built, 32).is_ok());
        assert!(matches!(
            validate_mtu(&built, 31),
            Err(ClientError::PacketExceedsMtu {
                actual: 32,
                mtu: 31
            })
        ));
    }

    #[test]
    fn mtu_validation_ignores_packets_without_a_network_layer() {
        let mut packet = Packet::new();
        packet.push(Ethernet {
            ether_type: WireValue::Exact(0x88b5),
            ..Ethernet::default()
        });
        packet.push(Raw::new(vec![0_u8; 32]));
        let built = build(packet);

        assert!(validate_mtu(&built, 1).is_ok());
    }
}
