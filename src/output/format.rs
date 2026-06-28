// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use super::ListenerEvent;

use serde::{Deserialize, Serialize};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutputFormat {
    /// Concise summary.
    Summary,
    /// Field-by-field breakdown.
    Detailed,
    /// Hexadecimal dump.
    Hex,
    /// Machine-readable JSON.
    Json,
}

const HEX_PREVIEW_BYTES: usize = 48;

pub(crate) fn format_hex(data: &[u8]) -> String {
    data.chunks(16)
        .enumerate()
        .map(|(idx, chunk)| {
            let offset = idx * 16;
            let hex_part = chunk
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join(" ");
            let ascii_part = chunk
                .iter()
                .map(|b| {
                    if b.is_ascii_graphic() || *b == b' ' {
                        *b as char
                    } else {
                        '.'
                    }
                })
                .collect::<String>();
            format!("{:04x}: {:<47}  {}", offset, hex_part, ascii_part)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub(crate) fn format_preview(data: &[u8]) -> String {
    let preview = data
        .iter()
        .take(HEX_PREVIEW_BYTES)
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(" ");
    if data.len() > HEX_PREVIEW_BYTES {
        format!("{} …", preview)
    } else {
        preview
    }
}

pub(crate) fn render_listener_hex(event: &ListenerEvent) -> (String, Option<String>) {
    if event.data.is_empty() {
        return (
            "no payload captured; re-run with --show-reply for full dump".to_string(),
            None,
        );
    }

    let body = format_hex(&event.data);
    let trailer = if event.truncated {
        Some(format!(
            "(payload preview truncated to {} bytes)",
            event.data.len()
        ))
    } else {
        None
    };

    (body, trailer)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use crate::output::ProtocolLabel;

    fn listener_event(data: Vec<u8>, show_payload: bool, truncated: bool) -> ListenerEvent {
        ListenerEvent {
            timestamp: SystemTime::now(),
            length: data.len(),
            layer2_source: None,
            layer2_destination: None,
            network_source: None,
            network_destination: None,
            network_protocol: Some("IPv4".to_string()),
            transport: Some("TCP".to_string()),
            detail: None,
            protocol_label: ProtocolLabel::Tcp,
            data,
            show_payload,
            truncated,
        }
    }

    #[test]
    fn format_hex_covers_empty_printable_nonprintable_and_line_boundaries() {
        assert_eq!(format_hex(&[]), "");

        let mixed = format_hex(b"A\x00B\x01");
        assert!(mixed.contains("0000:"));
        assert!(mixed.contains("41 00 42 01"));
        assert!(mixed.contains("A.B."));

        let one_line = format_hex(b"0123456789abcdef");
        assert!(one_line.contains("0000:"));
        assert!(!one_line.contains("0010:"));

        let two_lines = format_hex(b"0123456789abcdefX");
        assert!(two_lines.contains("0010:"));
    }

    #[test]
    fn format_preview_handles_empty_short_and_truncated_payloads() {
        assert_eq!(format_preview(b""), "");
        assert_eq!(format_preview(b"Hello"), "48 65 6c 6c 6f");

        let at_limit = vec![0x42u8; HEX_PREVIEW_BYTES];
        assert!(!format_preview(&at_limit).contains("…"));

        let over_limit = vec![0x42u8; HEX_PREVIEW_BYTES + 1];
        let preview = format_preview(&over_limit);
        assert!(preview.contains("…"));
        assert!(preview.split_whitespace().count() <= HEX_PREVIEW_BYTES + 1);
    }

    #[test]
    fn render_listener_hex_returns_dump_and_no_trailer_for_full_payload() {
        let event = listener_event((0u8..32).collect(), true, false);

        let (body, trailer) = render_listener_hex(&event);
        assert!(body.contains("0000:"));
        assert!(body.contains("0010:"));
        assert!(trailer.is_none());
    }

    #[test]
    fn render_listener_hex_includes_truncation_message() {
        let event = listener_event((0u8..48).collect(), false, true);

        let (body, trailer) = render_listener_hex(&event);
        assert!(body.contains("0000:"));
        assert!(body.contains("0020:"));
        assert_eq!(
            trailer,
            Some("(payload preview truncated to 48 bytes)".to_string())
        );
    }

    #[test]
    fn render_listener_hex_handles_empty_payload() {
        let event = listener_event(vec![], false, false);

        let (body, trailer) = render_listener_hex(&event);
        assert_eq!(
            body,
            "no payload captured; re-run with --show-reply for full dump"
        );
        assert!(trailer.is_none());
    }
}
