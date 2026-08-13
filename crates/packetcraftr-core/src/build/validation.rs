// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pre-encoding packet, binding, and padding-boundary validation.

use crate::{
    Packet,
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{MalformedLayer, Padding, ProtocolId, Raw},
    registry::ProtocolRegistry,
    semantics::BuiltinProtocol,
};

use super::{BuildError, BuildMode};

pub(super) fn validate_bindings(
    registry: &ProtocolRegistry,
    packet: &Packet,
    protocols: &[ProtocolId],
    mode: BuildMode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), BuildError> {
    debug_assert_eq!(protocols.len(), packet.len());
    for (index, layer) in packet.iter().enumerate() {
        let Some(padding) = layer.as_any().downcast_ref::<Padding>() else {
            continue;
        };
        if let Some(outside_layer) = padding.outside_layer {
            let Some(outside) = packet
                .layer(outside_layer)
                .filter(|_| outside_layer < index)
            else {
                return Err(BuildError::InvalidPaddingBoundary {
                    index,
                    outside_layer,
                });
            };
            if outside.as_any().is::<Padding>() || outside.as_any().is::<MalformedLayer>() {
                return Err(BuildError::InvalidPaddingBoundary {
                    index,
                    outside_layer,
                });
            }
            let outside_protocol = &protocols[outside_layer];
            let outside_builtin = BuiltinProtocol::from_id(outside_protocol);
            let child_protocol = packet
                .layer(outside_layer + 1)
                .and_then(|child| child.as_any().downcast_ref::<MalformedLayer>())
                .and_then(|child| child.intended_protocol.as_ref())
                .unwrap_or(&protocols[outside_layer + 1]);
            let link_declares_length = || match outside.field("ether_type") {
                Some(FieldValue::Unsigned(value)) => value <= 1500,
                Some(FieldValue::Bytes(value)) if value.len() == 2 => {
                    u16::from_be_bytes([value[0], value[1]]) <= 1500
                }
                _ => matches!(
                    BuiltinProtocol::from_id(child_protocol),
                    Some(BuiltinProtocol::Llc | BuiltinProtocol::Padding)
                ),
            };
            let has_declared_boundary = match outside_builtin {
                Some(
                    BuiltinProtocol::Ipv4
                    | BuiltinProtocol::Ipv6
                    | BuiltinProtocol::Udp
                    | BuiltinProtocol::Arp
                    | BuiltinProtocol::Pppoe,
                ) => true,
                Some(
                    BuiltinProtocol::Ethernet | BuiltinProtocol::Vlan | BuiltinProtocol::Vlan8021ad,
                ) => link_declares_length(),
                _ => false,
            };
            if !has_declared_boundary {
                if mode == BuildMode::Strict {
                    return Err(BuildError::InvalidPaddingBoundary {
                        index,
                        outside_layer,
                    });
                }
                diagnostics.push(
                    Diagnostic::warning(
                        "build.unsupported_padding_boundary",
                        format!("layer {outside_protocol} has no independent wire-length boundary"),
                    )
                    .at_layer(index),
                );
            }
            if matches!(
                outside_builtin,
                Some(
                    BuiltinProtocol::Ipv4
                        | BuiltinProtocol::Ipv6
                        | BuiltinProtocol::Udp
                        | BuiltinProtocol::Pppoe
                )
            ) {
                diagnostics.push(
                    Diagnostic::warning(
                        "build.padding_outside_network_length",
                        "preserving bytes outside a declared network or datagram length",
                    )
                    .at_layer(index),
                );
            }
            continue;
        }
        let enclosed_by_link = protocols.iter().take(index).any(|protocol| {
            matches!(
                BuiltinProtocol::from_id(protocol),
                Some(
                    BuiltinProtocol::Ethernet
                        | BuiltinProtocol::BsdNull
                        | BuiltinProtocol::BsdLoop
                        | BuiltinProtocol::LinuxSll
                        | BuiltinProtocol::LinuxSll2
                )
            )
        });
        if enclosed_by_link {
            continue;
        }
        if mode == BuildMode::Strict {
            return Err(BuildError::PaddingWithoutLinkLayer { index });
        }
        diagnostics.push(
            Diagnostic::warning(
                "build.padding_without_link_layer",
                "bytes outside all declared protocol lengths require a link-layer envelope",
            )
            .at_layer(index),
        );
    }

    let mut previous_binding = None;
    for index in 0..packet.len().saturating_sub(1) {
        let parent = &protocols[index];
        let child = &protocols[index + 1];
        let discriminator = match previous_binding {
            Some((previous_parent, previous_child, discriminator))
                if previous_parent == parent && previous_child == child =>
            {
                discriminator
            }
            _ => {
                let discriminator = registry.discriminator_for(parent.as_str(), child.as_str());
                previous_binding = Some((parent, child, discriminator));
                discriminator
            }
        };
        if discriminator.is_some()
            || BuiltinProtocol::from_id(parent) == Some(BuiltinProtocol::Raw)
            || matches!(
                BuiltinProtocol::from_id(child),
                Some(BuiltinProtocol::Padding | BuiltinProtocol::Malformed)
            )
        {
            continue;
        }
        if mode == BuildMode::Strict {
            return Err(BuildError::UnboundLayers {
                parent: parent.clone(),
                child: child.clone(),
            });
        }
        diagnostics.push(
            Diagnostic::warning(
                "build.unbound_layers",
                format!("no registered binding from {parent} to {child}"),
            )
            .at_layer(index),
        );
    }
    Ok(())
}

pub(super) fn pass_through_byte_length(packet: &Packet) -> Result<usize, BuildError> {
    packet.iter().try_fold(0_usize, |total, layer| {
        let layer = layer.as_any();
        let length = if let Some(layer) = layer.downcast_ref::<Raw>() {
            layer.bytes.len()
        } else if let Some(layer) = layer.downcast_ref::<Padding>() {
            layer.bytes.len()
        } else if let Some(layer) = layer.downcast_ref::<MalformedLayer>() {
            layer.bytes.len()
        } else {
            0
        };
        total.checked_add(length).ok_or(BuildError::LengthOverflow)
    })
}
