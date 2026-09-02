// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pre-encoding packet, binding, and padding-boundary validation.

use crate::{
    Packet,
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Malformed, Padding, Raw},
    protocol::BuiltinProtocol,
    registry::Registry,
};

use super::Error;

pub(super) fn validate_bindings(
    registry: &Registry,
    packet: &Packet,
    protocols: &[crate::layer::Id],
    mode: super::Mode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), Error> {
    debug_assert_eq!(protocols.len(), packet.len());
    for (index, layer) in packet.iter().enumerate() {
        let Some(padding) = layer.as_any().downcast_ref::<Padding>() else {
            continue;
        };
        validate_padding(packet, protocols, index, padding, mode, diagnostics)?;
    }
    validate_adjacent_bindings(registry, packet, protocols, mode, diagnostics)
}

fn validate_adjacent_bindings(
    registry: &Registry,
    packet: &Packet,
    protocols: &[crate::layer::Id],
    mode: super::Mode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), Error> {
    let mut previous_binding = None;
    for index in 0..packet.len().saturating_sub(1) {
        #[expect(
            clippy::indexing_slicing,
            clippy::arithmetic_side_effects,
            reason = "`protocols.len() == packet.len()` and `index + 1` stays below that length"
        )]
        let (parent, child) = (&protocols[index], &protocols[index + 1]);
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
            || BuiltinProtocol::from_id(*parent) == Some(BuiltinProtocol::Raw)
            || matches!(
                BuiltinProtocol::from_id(*child),
                Some(BuiltinProtocol::Padding | BuiltinProtocol::Malformed)
            )
        {
            continue;
        }
        if mode == super::Mode::Strict {
            return Err(Error::UnboundLayers {
                parent: *parent,
                child: *child,
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

fn validate_padding(
    packet: &Packet,
    protocols: &[crate::layer::Id],
    index: usize,
    padding: &Padding,
    mode: super::Mode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), Error> {
    let Some(outside_layer) = padding.outside_layer else {
        return validate_link_padding(protocols, index, mode, diagnostics);
    };
    let Some(outside) = packet
        .layer(outside_layer)
        .filter(|_| outside_layer < index)
    else {
        return Err(Error::InvalidPaddingBoundary {
            index,
            outside_layer,
        });
    };
    if outside.as_any().is::<Padding>() || outside.as_any().is::<Malformed>() {
        return Err(Error::InvalidPaddingBoundary {
            index,
            outside_layer,
        });
    }
    let Some(outside_protocol) = protocols.get(outside_layer) else {
        return Err(Error::InvalidPaddingBoundary {
            index,
            outside_layer,
        });
    };
    let outside_builtin = BuiltinProtocol::from_id(*outside_protocol);
    let child_layer = outside_layer
        .checked_add(1)
        .ok_or(Error::InvalidPaddingBoundary {
            index,
            outside_layer,
        })?;
    let Some(declared_child) = protocols.get(child_layer) else {
        return Err(Error::InvalidPaddingBoundary {
            index,
            outside_layer,
        });
    };
    let child_protocol = packet
        .layer(child_layer)
        .and_then(|child| child.as_any().downcast_ref::<Malformed>())
        .and_then(|child| child.intended_protocol.as_deref())
        .unwrap_or(declared_child.as_str());
    let link_declares_length = || match outside.field("ether_type") {
        Some(FieldValue::Unsigned(value)) => value <= 1500,
        #[expect(
            clippy::indexing_slicing,
            reason = "the guard admits this arm only when `value.len() == 2`"
        )]
        Some(FieldValue::Bytes(value)) if value.len() == 2 => {
            u16::from_be_bytes([value[0], value[1]]) <= 1500
        }
        _ => matches!(
            BuiltinProtocol::from_name(child_protocol),
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
        Some(BuiltinProtocol::Ethernet | BuiltinProtocol::Vlan | BuiltinProtocol::Vlan8021ad) => {
            link_declares_length()
        }
        _ => false,
    };
    if !has_declared_boundary {
        if mode == super::Mode::Strict {
            return Err(Error::InvalidPaddingBoundary {
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
    if is_network_boundary(outside_builtin) {
        diagnostics.push(
            Diagnostic::warning(
                "build.padding_outside_network_length",
                "preserving bytes outside a declared network or datagram length",
            )
            .at_layer(index),
        );
    }
    Ok(())
}

fn validate_link_padding(
    protocols: &[crate::layer::Id],
    index: usize,
    mode: super::Mode,
    diagnostics: &mut Vec<Diagnostic>,
) -> Result<(), Error> {
    let enclosed_by_link = protocols.iter().take(index).any(|protocol| {
        matches!(
            BuiltinProtocol::from_id(*protocol),
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
        return Ok(());
    }
    if mode == super::Mode::Strict {
        return Err(Error::PaddingWithoutLinkLayer { index });
    }
    diagnostics.push(
        Diagnostic::warning(
            "build.padding_without_link_layer",
            "bytes outside all declared protocol lengths require a link-layer envelope",
        )
        .at_layer(index),
    );
    Ok(())
}

fn is_network_boundary(protocol: Option<BuiltinProtocol>) -> bool {
    matches!(
        protocol,
        Some(
            BuiltinProtocol::Ipv4
                | BuiltinProtocol::Ipv6
                | BuiltinProtocol::Udp
                | BuiltinProtocol::Pppoe
        )
    )
}

pub(super) fn pass_through_byte_length(packet: &Packet) -> Result<usize, Error> {
    packet.iter().try_fold(0_usize, |total, layer| {
        let layer = layer.as_any();
        let length = if let Some(layer) = layer.downcast_ref::<Raw>() {
            layer.bytes.len()
        } else if let Some(layer) = layer.downcast_ref::<Padding>() {
            layer.bytes.len()
        } else if let Some(layer) = layer.downcast_ref::<Malformed>() {
            layer.bytes.len()
        } else {
            0
        };
        total.checked_add(length).ok_or(Error::LengthOverflow)
    })
}
