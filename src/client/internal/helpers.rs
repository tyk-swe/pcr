use std::net::IpAddr;
use std::time::Instant;

use bytes::Bytes;

use crate::net::{
    CaptureQueueLimits, CaptureSession, IoSendReport, LiveIoError, MaterializedRoute, PlannedRoute,
};
use crate::packet::internal::{BuildContext, BuiltPacket, FieldValue, Packet, Padding};
use crate::protocol::internal::Ethernet;

use super::exchange::{CaptureGuard, ExchangeOptions, MAX_EXCHANGE_TIMEOUT};
use super::send::ClientError;
use super::target::IpVersion;

impl ExchangeOptions {
    /// Validates every finite timeout and aggregate retention bound before a
    /// resolver, route, neighbor, capture, or transmission provider is used.
    pub fn validate(&self) -> Result<CaptureQueueLimits, ClientError> {
        if self.timeout > MAX_EXCHANGE_TIMEOUT {
            return Err(ClientError::InvalidExchangeOption {
                field: "timeout",
                message: format!("must not exceed {MAX_EXCHANGE_TIMEOUT:?}"),
            });
        }
        if self.max_template_packets == 0 {
            return Err(ClientError::InvalidExchangeOption {
                field: "max_template_packets",
                message: "must be greater than zero".to_owned(),
            });
        }
        for (field, value) in [
            ("max_responses", self.max_responses),
            ("max_unsolicited", self.max_unsolicited),
        ] {
            if value > self.max_capture_queue_frames {
                return Err(ClientError::InvalidExchangeOption {
                    field,
                    message: format!(
                        "{value} exceeds aggregate capture frame ceiling {}",
                        self.max_capture_queue_frames
                    ),
                });
            }
        }
        Instant::now().checked_add(self.timeout).ok_or_else(|| {
            ClientError::InvalidExchangeOption {
                field: "timeout",
                message: "cannot be represented by the platform monotonic clock".to_owned(),
            }
        })?;
        CaptureQueueLimits {
            max_frames: self.max_capture_queue_frames,
            max_bytes: self.max_captured_bytes,
            snap_length: self.decode.max_packet_size,
            overflow_policy: self.capture_overflow_policy,
        }
        .validate()
        .map_err(ClientError::from)
    }
}

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
        matches!(layer.protocol_id().as_str(), "ipv4" | "ipv6").then_some(index)
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

pub(super) fn error_after_shutdown<C: CaptureSession>(
    capture: &mut CaptureGuard<C>,
    operation: LiveIoError,
) -> ClientError {
    match capture.shutdown() {
        Ok(()) => ClientError::Io(operation),
        Err(shutdown) => ClientError::OperationAndCaptureShutdown {
            operation,
            shutdown,
        },
    }
}

pub(super) fn push_diagnostic_once(
    diagnostics: &mut Vec<crate::packet::internal::Diagnostic>,
    diagnostic: crate::packet::internal::Diagnostic,
) {
    if !diagnostics
        .iter()
        .any(|existing| existing.code == diagnostic.code)
    {
        diagnostics.push(diagnostic);
    }
}

pub(super) fn reserve_capture_evidence(
    retained_frames: &mut usize,
    retained_bytes: &mut usize,
    additional: usize,
    frame_limit: usize,
    byte_limit: usize,
    diagnostics: &mut Vec<crate::packet::internal::Diagnostic>,
) -> bool {
    let Some(frame_total) = retained_frames.checked_add(1) else {
        push_diagnostic_once(
            diagnostics,
            crate::packet::internal::Diagnostic::warning(
                "exchange.capture_frame_limit",
                "retained capture frame accounting overflowed; frame was not retained",
            ),
        );
        return false;
    };
    if frame_total > frame_limit {
        push_diagnostic_once(
            diagnostics,
            crate::packet::internal::Diagnostic::warning(
                "exchange.capture_frame_limit",
                format!(
                    "aggregate retained capture frame limit {frame_limit} reached; later frames were not retained"
                ),
            ),
        );
        return false;
    }
    let Some(byte_total) = retained_bytes.checked_add(additional) else {
        push_diagnostic_once(
            diagnostics,
            crate::packet::internal::Diagnostic::warning(
                "exchange.capture_byte_limit",
                "retained capture byte accounting overflowed; frame was not retained",
            ),
        );
        return false;
    };
    if byte_total > byte_limit {
        push_diagnostic_once(
            diagnostics,
            crate::packet::internal::Diagnostic::warning(
                "exchange.capture_byte_limit",
                format!(
                    "retained capture byte limit {byte_limit} reached; later frames were not retained"
                ),
            ),
        );
        return false;
    }
    *retained_frames = frame_total;
    *retained_bytes = byte_total;
    true
}

pub(super) fn build_context(plan: &PlannedRoute) -> BuildContext {
    BuildContext {
        source: plan.packet_source,
        destination: plan.final_destination,
        mtu: Some(plan.route.mtu),
        link_type: Some(plan.route.link_type.0),
        metadata: Default::default(),
    }
}

pub(super) fn materialize_link_structure(
    packet: &mut Packet,
    plan: &PlannedRoute,
) -> Result<(), ClientError> {
    if !plan.synthesized_ethernet
        || packet
            .iter()
            .any(|layer| layer.protocol_id().as_str() == "ethernet")
    {
        return Ok(());
    }
    packet
        .insert(0, Ethernet::default())
        .map_err(|source| ClientError::PacketMaterialization {
            layer: 0,
            field: "ethernet",
            message: source.to_string(),
        })?;
    Ok(())
}

pub(super) fn materialize_network_fields(
    packet: &mut Packet,
    plan: &PlannedRoute,
) -> Result<(), ClientError> {
    for index in 0..packet.len() {
        let Some(layer) = packet.layer_mut(index) else {
            continue;
        };
        let protocol = layer.protocol_id();
        let ip_version = match protocol.as_str() {
            "ipv4" => IpVersion::V4,
            "ipv6" => IpVersion::V6,
            _ => continue,
        };
        let source_unspecified = match layer.field("source") {
            Some(FieldValue::Ipv4(value)) => value.is_unspecified(),
            Some(FieldValue::Ipv6(value)) => value.is_unspecified(),
            _ => false,
        };
        if source_unspecified {
            let value = match (ip_version, plan.packet_source) {
                (IpVersion::V4, Some(IpAddr::V4(value))) => FieldValue::Ipv4(value),
                (IpVersion::V6, Some(IpAddr::V6(value))) => FieldValue::Ipv6(value),
                _ => {
                    return Err(ClientError::PacketMaterialization {
                        layer: index,
                        field: "source",
                        message: "route source family does not match the packet layer".to_owned(),
                    });
                }
            };
            layer.set_field("source", value).map_err(|source| {
                ClientError::PacketMaterialization {
                    layer: index,
                    field: "source",
                    message: source.to_string(),
                }
            })?;
        }

        let destination_unspecified = match layer.field("destination") {
            Some(FieldValue::Ipv4(value)) => value.is_unspecified(),
            Some(FieldValue::Ipv6(value)) => value.is_unspecified(),
            _ => false,
        };
        if destination_unspecified {
            let value = match (ip_version, plan.lookup_destination) {
                (IpVersion::V4, Some(IpAddr::V4(value))) => FieldValue::Ipv4(value),
                (IpVersion::V6, Some(IpAddr::V6(value))) => FieldValue::Ipv6(value),
                _ => {
                    return Err(ClientError::PacketMaterialization {
                        layer: index,
                        field: "destination",
                        message: "route destination family does not match the packet layer"
                            .to_owned(),
                    });
                }
            };
            layer.set_field("destination", value).map_err(|source| {
                ClientError::PacketMaterialization {
                    layer: index,
                    field: "destination",
                    message: source.to_string(),
                }
            })?;
        }
    }
    Ok(())
}

pub(super) fn materialize_link_fields(
    packet: &mut Packet,
    route: &MaterializedRoute,
) -> Result<bool, ClientError> {
    if route.plan.mode != crate::net::LinkMode::Layer2 {
        return Ok(false);
    }
    let Some(index) = packet
        .iter()
        .position(|layer| layer.protocol_id().as_str() == "ethernet")
    else {
        return Ok(false);
    };
    let layer = packet
        .layer_mut(index)
        .expect("position returned an existing layer");
    let mut changed = false;
    if matches!(
        layer.field("source"),
        Some(FieldValue::Mac(value)) if value == [0; 6]
    ) {
        let source_mac =
            route
                .plan
                .source_mac
                .ok_or_else(|| ClientError::PacketMaterialization {
                    layer: index,
                    field: "source",
                    message: "route has no interface-owned source MAC".to_owned(),
                })?;
        layer
            .set_field("source", FieldValue::Mac(source_mac.0))
            .map_err(|source| ClientError::PacketMaterialization {
                layer: index,
                field: "source",
                message: source.to_string(),
            })?;
        changed = true;
    }
    if matches!(
        layer.field("destination"),
        Some(FieldValue::Mac(value)) if value == [0; 6]
    ) {
        let destination_mac =
            route
                .plan
                .destination_mac
                .ok_or_else(|| ClientError::PacketMaterialization {
                    layer: index,
                    field: "destination",
                    message: "route has no resolved destination MAC".to_owned(),
                })?;
        layer
            .set_field("destination", FieldValue::Mac(destination_mac.0))
            .map_err(|source| ClientError::PacketMaterialization {
                layer: index,
                field: "destination",
                message: source.to_string(),
            })?;
        changed = true;
    }
    Ok(changed)
}

pub(super) fn require_fixed_width_link_materialization(
    preliminary_len: usize,
    materialized_len: usize,
) -> Result<(), ClientError> {
    if materialized_len != preliminary_len {
        // Only fixed-width MAC fields may change after the preliminary build.
        // Treat a custom codec violating that contract as a materialization
        // error rather than authorizing or accounting for a different shape.
        return Err(ClientError::PacketMaterialization {
            layer: 0,
            field: "ethernet",
            message: format!(
                "link materialization changed frame length from {preliminary_len} to {materialized_len} bytes"
            ),
        });
    }
    Ok(())
}

pub(super) fn is_public(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_multicast()
                || !(address.is_private()
                    || address.is_loopback()
                    || address.is_link_local()
                    || address.is_unspecified()
                    || address.is_documentation())
        }
        IpAddr::V6(address) => {
            address.is_multicast()
                || !(address.is_loopback()
                    || address.is_unspecified()
                    || address.is_unique_local()
                    || address.is_unicast_link_local()
                    || is_ipv6_documentation(address))
        }
    }
}

fn is_ipv6_documentation(address: std::net::Ipv6Addr) -> bool {
    let segments = address.segments();
    segments[0] == 0x2001 && segments[1] == 0x0db8
}
