// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! CLI rendering pipeline for machine serialization, stream sequencing, capture files, and styled human terminal output.

mod capture_file;
mod human;
mod machine;
mod sequence;
mod style;

pub(crate) use capture_file::{capture_file_format, write_capture_file, write_raw};

pub(crate) use human::{
    emit_stderr_document, emit_stderr_error, emit_stderr_message, emit_stdout_document,
    render_diagnostics_text, render_output_diagnostics_text, write_plain_line, write_stdout_line,
};

#[cfg(test)]
pub(crate) use human::capture_stdout;

pub(crate) use machine::{emit_json, emit_json_compact, output_timestamp_text, spaced_hex};

pub(crate) use sequence::{emit_stream_record, next_stream_sequence};

pub(crate) use style::terminal_document;

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use packetcraftr::{
        capture::{Frame, LinkType, Reader},
        output,
    };

    use super::capture_file::encode_capture_file;
    use super::style::{terminal_safe, terminal_safe_document};
    use super::{next_stream_sequence, output_timestamp_text, terminal_document};

    #[test]
    fn terminal_text_escapes_controls_and_directional_overrides() {
        let safe = terminal_safe("line\n\u{1b}[31m\u{2028}next\u{2029}\u{202e}tail");
        assert_eq!(
            safe,
            "line\\n\\u{1b}[31m\\u{2028}next\\u{2029}\\u{202e}tail"
        );
        assert!(!safe.chars().any(char::is_control));
        assert!(!safe.contains(['\u{2028}', '\u{2029}']));
    }

    #[test]
    fn terminal_documents_preserve_layout_but_escape_terminal_controls() {
        let safe = terminal_safe_document("first\r\nsecond\n\t\u{1b}[31m\u{202e}tail");
        assert_eq!(safe, "first\nsecond\n\\t\\u{1b}[31m\\u{202e}tail");
        assert_eq!(safe.lines().count(), 3);
        assert!(!safe.contains('\u{1b}'));
        assert!(!safe.contains('\u{202e}'));

        let cleaned = terminal_document("\u{1b}[31merror:\u{1b}[0m bad\nnext");
        assert_eq!(cleaned, "error: bad\nnext");
    }

    #[test]
    fn pre_epoch_timestamp_text_uses_conventional_signed_decimal_notation() {
        assert_eq!(
            output_timestamp_text(output::capture::Timestamp {
                unix_seconds: -3,
                nanoseconds: 750_000_000,
            }),
            "-2.250000000"
        );
        assert_eq!(
            output_timestamp_text(output::capture::Timestamp {
                unix_seconds: -1,
                nanoseconds: 500_000_000,
            }),
            "-0.500000000"
        );
    }

    #[test]
    fn stream_sequence_advances_and_fails_closed_at_the_wire_limit() {
        assert_eq!(next_stream_sequence(0).unwrap(), 1);
        assert_eq!(next_stream_sequence(u64::MAX - 1).unwrap(), u64::MAX);

        let error = next_stream_sequence(u64::MAX).unwrap_err();
        assert_eq!(error.sequence, Some(u64::MAX));
        assert_eq!(error.classification.code, "internal.output_sequence");
    }

    #[test]
    fn pcapng_exchange_evidence_preserves_multiple_link_types() {
        let raw = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, vec![0x45, 0, 0, 0]).unwrap();
        let ethernet = Frame::new(
            SystemTime::UNIX_EPOCH + Duration::from_nanos(1),
            LinkType::ETHERNET,
            vec![0; 14],
        )
        .unwrap();
        let bytes = encode_capture_file(
            output::contract::Format::Pcapng,
            [raw.clone(), ethernet.clone()],
        )
        .unwrap();
        let mut reader = Reader::new(std::io::Cursor::new(bytes)).unwrap();
        let decoded_raw = reader.next_frame().unwrap().unwrap();
        let decoded_ethernet = reader.next_frame().unwrap().unwrap();

        assert_eq!(decoded_raw.link_type, raw.link_type);
        assert_eq!(decoded_raw.bytes(), raw.bytes());
        assert_eq!(decoded_raw.interface, Some(0));
        assert_eq!(decoded_ethernet.link_type, ethernet.link_type);
        assert_eq!(decoded_ethernet.bytes(), ethernet.bytes());
        assert_eq!(decoded_ethernet.interface, Some(1));
        assert!(reader.next_frame().unwrap().is_none());

        let error =
            encode_capture_file(output::contract::Format::Pcap, [raw, ethernet]).unwrap_err();
        assert_eq!(error.exit_code, 5);
        assert!(error.message.contains("link type"));
    }
}
