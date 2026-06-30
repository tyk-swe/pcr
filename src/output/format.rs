// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use serde::{Deserialize, Serialize};

use crate::domain::event::ListenerEvent;

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
