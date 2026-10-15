// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::Write as _;

use crate::errors::CliError;
use crate::output::quic::{Conversation, PacketCounts, Summary};
use crate::rendering::{
    comma_separated, duration_text, optional_display, write_stdout_line, write_summary_line,
};

fn list_text(values: &[u32]) -> String {
    if values.is_empty() {
        "none".to_owned()
    } else {
        comma_separated(values)
    }
}

pub(super) fn render_conversation(
    invocation: &crate::invocation::Invocation,
    conversation: &Conversation,
) -> Result<(), CliError> {
    let mut line = format!(
        "udp stream {} scope={} interface={} encapsulation={}: {} <-> {} packets {} ({})",
        conversation.stream,
        conversation.scope.id,
        optional_display(conversation.scope.interface),
        crate::rendering::encapsulation_text(&conversation.scope.encapsulation),
        std::net::SocketAddr::new(conversation.address_a, conversation.port_a),
        std::net::SocketAddr::new(conversation.address_b, conversation.port_b),
        conversation.packets.total(),
        packet_counts_text(&conversation.packets),
    );
    if let Some(dcid) = &conversation.initial_dcid_hex {
        let _ = write!(line, " initial_dcid={dcid}");
    }
    if let Some(scid) = &conversation.initial_scid_hex {
        let _ = write!(line, " initial_scid={scid}");
    }
    let _ = write!(
        line,
        " versions={} version_negotiation_offers={}",
        list_text(&conversation.versions),
        list_text(&conversation.negotiated),
    );
    if conversation.versions_omitted > 0 {
        let _ = write!(line, " versions_omitted={}", conversation.versions_omitted);
    }
    if conversation.negotiated_omitted > 0 {
        let _ = write!(
            line,
            " version_negotiation_offers_omitted={}",
            conversation.negotiated_omitted
        );
    }
    let _ = write!(line, " duration {}", duration_text(conversation.duration));
    write_stdout_line(invocation, format_args!("{line}"))
}

pub(super) fn render_summary(
    invocation: &crate::invocation::Invocation,
    summary: &Summary,
) -> Result<(), CliError> {
    write_summary_line(
        invocation,
        format_args!(
            "quic conversations={} quic_conversations={} packets={} malformed={} \
             non_quic_datagrams={} frames_matched={} frames_read={}",
            summary.conversations,
            summary.quic_conversations,
            summary.packets,
            summary.malformed,
            summary.non_quic_datagrams,
            summary.frames_matched,
            summary.frames_read,
        ),
    )?;
    if let Some(reason) = summary.first_malformed {
        write_stdout_line(invocation, format_args!("first malformed packet: {reason}"))?;
    }
    Ok(())
}

fn packet_counts_text(counts: &PacketCounts) -> String {
    let mut text = format!(
        "initial {} / zero_rtt {} / handshake {} / retry {} / version_negotiation {} / one_rtt {}",
        counts.initial,
        counts.zero_rtt,
        counts.handshake,
        counts.retry,
        counts.version_negotiation,
        counts.one_rtt,
    );
    if counts.malformed > 0 {
        let _ = write!(text, " / malformed {}", counts.malformed);
    }
    text
}
