// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use crate::domain::event::ListenerEvent;

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OutputFormat {
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
    use super::*;
    #[cfg(feature = "pcap")]
    use crate::domain::event::ProtocolLabel;
    use std::time::SystemTime;

    fn event(data: Vec<u8>, truncated: bool) -> ListenerEvent {
        ListenerEvent {
            timestamp: SystemTime::UNIX_EPOCH,
            length: data.len(),
            layer2_source: None,
            layer2_destination: None,
            network_source: None,
            network_destination: None,
            network_protocol: None,
            transport: None,
            detail: None,
            #[cfg(feature = "pcap")]
            protocol_label: ProtocolLabel::Unknown,
            data,
            show_payload: true,
            truncated,
        }
    }

    #[test]
    fn format_hex_includes_offsets_hex_and_ascii() {
        let formatted = format_hex(b"ABC\x00DEF");

        assert!(formatted.starts_with("0000: 41 42 43 00 44 45 46"));
        assert!(formatted.ends_with("ABC.DEF"));
    }

    #[test]
    fn format_hex_wraps_at_sixteen_bytes() {
        let formatted = format_hex(&(0u8..18).collect::<Vec<_>>());

        assert!(formatted.contains("0000:"));
        assert!(formatted.contains("0010: 10 11"));
    }

    #[test]
    fn format_preview_truncates_after_preview_limit() {
        let preview = format_preview(&(0u8..50).collect::<Vec<_>>());

        assert!(preview.ends_with(" …"));
        assert!(preview.starts_with("00 01 02"));
    }

    #[test]
    fn render_listener_hex_handles_empty_data() {
        let (body, trailer) = render_listener_hex(&event(vec![], false));

        assert_eq!(
            body,
            "no payload captured; re-run with --show-reply for full dump"
        );
        assert_eq!(trailer, None);
    }

    #[test]
    fn render_listener_hex_includes_truncation_trailer() {
        let (body, trailer) = render_listener_hex(&event(b"hello".to_vec(), true));

        assert!(body.contains("68 65 6c 6c 6f"));
        assert_eq!(
            trailer,
            Some("(payload preview truncated to 5 bytes)".to_string())
        );
    }
}
