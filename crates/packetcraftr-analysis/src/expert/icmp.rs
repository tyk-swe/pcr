// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_packet::diagnostic::DiagnosticSeverity;
use packetcraftr_protocol::{QuotedIcmpError, quoted_icmp_error};

use super::{Finding, FlowKey, FrameRecord, new_finding, tcp_stream_ref, udp_stream_ref};

pub(super) fn observe(record: &FrameRecord<'_>, findings: &mut Vec<Finding>) {
    let Some(error) = quoted_icmp_error(&record.decoded.packet) else {
        return;
    };
    if error.response_destination != error.quoted.source {
        return;
    }
    let Some((source_port, destination_port)) = error.quoted.transport_ports() else {
        return;
    };
    let flow = FlowKey {
        source: error.quoted.source,
        source_port,
        destination: error.quoted.destination,
        destination_port,
    };
    let (protocol, stream) = match error.quoted.protocol {
        6 => ("TCP", record.tcp_stream_for(&flow).map(tcp_stream_ref)),
        17 => ("UDP", record.udp_stream_for(&flow).map(udp_stream_ref)),
        _ => return,
    };
    let (severity, code, kind) = match error.kind {
        QuotedIcmpError::TimeExceeded => (
            DiagnosticSeverity::Info,
            "icmp.time_exceeded",
            "time exceeded",
        ),
        QuotedIcmpError::PortUnreachable => (
            DiagnosticSeverity::Info,
            "icmp.port_unreachable",
            "port unreachable",
        ),
        QuotedIcmpError::DestinationUnreachable => (
            DiagnosticSeverity::Warning,
            "icmp.destination_unreachable",
            "destination unreachable",
        ),
        QuotedIcmpError::AdministrativelyProhibited => (
            DiagnosticSeverity::Warning,
            "icmp.administratively_prohibited",
            "administratively prohibited",
        ),
    };
    findings.push(new_finding(
        severity,
        code,
        record.number,
        stream,
        format!(
            "responder {} reported {kind} for quoted {protocol} flow {}:{} -> {}:{}",
            error.responder, flow.source, flow.source_port, flow.destination, flow.destination_port,
        ),
    ));
}
