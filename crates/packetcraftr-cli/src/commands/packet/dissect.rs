// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::output::contract::Format;

use packetcraftr_core::error::Kind;

pub(in crate::commands) mod arguments;

use std::sync::Arc;
use std::time::SystemTime;

use packetcraftr_core as core;
use packetcraftr_core::decode::DecodedPacket;
use packetcraftr_core::frame::Frame;

use crate::output;

use self::arguments::Args;
use crate::errors::CliError;
use crate::filtering::{self, Capabilities};
use crate::input::{
    InputKind, hex_text_limit, missing_input_error, read_bounded_file, read_stdin_bounded,
};
use crate::rendering::{
    FieldTree, emit_published, emit_stderr_message, render_diagnostics_text, render_dns_records,
    write_hex_line, write_raw, write_stdout_line, write_summary_line,
};

impl crate::commands::Spec for Args {
    const FORMATS: &'static [crate::output::contract::Format] = &[
        crate::output::contract::Format::Text,
        crate::output::contract::Format::Json,
        crate::output::contract::Format::Ndjson,
        crate::output::contract::Format::Hex,
        crate::output::contract::Format::Raw,
    ];
    const CANCELLATION: bool = false;

    fn resources(&self, settings: &mut crate::resources::Settings<'_>) {
        crate::resources::declare!(settings, self, [max_projection_bytes: Bytes @ ResultRetention]);
        self.budget.resources(settings);
        self.tree.resources(settings);
    }

    fn run(
        self,
        invocation: &crate::invocation::Invocation,
    ) -> Result<crate::commands::CommandExit, CliError> {
        let format = invocation.format;
        let stream = &invocation.output;
        run(invocation, self, format, stream).map(|()| crate::commands::CommandExit::SUCCESS)
    }
}

pub(super) fn run(
    invocation: &crate::invocation::Invocation,
    arguments: Args,
    format: Format,
    stream: &crate::invocation::StreamEncoder,
) -> Result<(), CliError> {
    arguments
        .tree
        .validate_format(format == Format::Text, format)?;
    let registry = arguments.decode.registry()?;
    if arguments.fields.is_empty() && matches!(format, Format::Ndjson) {
        return Err(crate::rendering::missing_fields_error());
    }
    let projector = crate::rendering::Projector::prepare(
        &arguments.fields,
        arguments.max_projection_bytes,
        &registry,
        output::contract::Command::Dissect,
        format,
    )?;
    if projector
        .as_ref()
        .is_some_and(|projector| projector.projection.requirements().stream_index)
    {
        return Err(CliError::new(
            Kind::Usage,
            "dissect cannot assign stream indexes; use packetcraftr files read with --field",
        ));
    }
    let max_packet_size = arguments.budget.max_packet_size;
    // A bad filter fails before any input is read.
    let filter = arguments
        .filter
        .as_deref()
        .map(|source| filtering::compile(source, &registry, Capabilities::frames_only()))
        .transpose()?;
    let hex_limit = hex_text_limit(max_packet_size);
    let bytes = match (arguments.hex, arguments.hex_file, arguments.file) {
        (Some(value), None, None) if value == "-" => hex_frame_bytes(
            &read_stdin_bounded(hex_limit, InputKind::FrameHex)?,
            max_packet_size,
        )?,
        (Some(value), None, None) => hex_frame_bytes(value.as_bytes(), max_packet_size)?,
        (None, Some(path), None) => hex_frame_bytes(
            &read_bounded_file(&path, hex_limit, InputKind::FrameHex)?,
            max_packet_size,
        )?,
        (None, None, Some(path)) => read_bounded_file(&path, max_packet_size, InputKind::Frame)?,
        (None, None, None) => read_stdin_bounded(max_packet_size, InputKind::Frame)?,
        _ => unreachable!("clap enforces conflicts"),
    };
    let mut tree = arguments
        .tree
        .tree
        .then(|| FieldTree::new(Arc::clone(&registry), arguments.tree.max_tree_bytes));
    let decoded = core::decode::Dissector::new(registry)
        .decode(
            Frame::new(SystemTime::now(), arguments.link_type, bytes)
                .map_err(CliError::classified)?,
            arguments.budget.decode_options(),
        )
        .map_err(CliError::classified)?;
    let context = core::filter::Context::frame(&decoded, 1);
    // The filter selects emission, not validity.
    let kept = match &filter {
        Some(filter) => filtering::matches_decoded(filter, &context)?,
        None => true,
    };
    if let Some(mut projector) = projector {
        if kept {
            let values = projector
                .projection
                .values(&context, projector.remaining())
                .map_err(CliError::classified)?;
            projector.emit(1, values, stream)?;
        }
        return projector.finish(
            invocation,
            1,
            u64::from(decoded.frame.captured_length()),
            stream,
        );
    }
    // An unmatched frame keeps byte-oriented stdout empty on success.
    if !kept && !matches!(format, Format::Json) {
        return emit_stderr_message("frame did not match the filter");
    }
    match format {
        Format::Text => render_text(invocation, &decoded, tree.as_mut(), stream.presentation()),
        Format::Hex => write_hex_line(decoded.frame.bytes()),
        Format::Raw => write_raw(decoded.frame.bytes()),
        Format::Json => emit_published(
            invocation,
            output::contract::Command::Dissect,
            output::envelope::Published::<output::dissect::AggregateResult>::from((kept, decoded)),
        ),
        Format::Ndjson => Err(CliError::new(
            Kind::Internal,
            "--field output returned before dissection rendering",
        )),
        other => other.unreachable(),
    }
}

fn render_text(
    invocation: &crate::invocation::Invocation,
    decoded: &DecodedPacket,
    tree: Option<&mut FieldTree>,
    presentation: crate::invocation::Presentation,
) -> Result<(), CliError> {
    write_summary_line(
        invocation,
        format_args!(
            "decoded {} bytes into {} layer(s)",
            decoded.frame.bytes().len(),
            decoded.packet.len()
        ),
    )?;
    let packet = core::document::Packet::from_packet(&decoded.packet);
    match tree {
        Some(tree) => {
            tree.render_layers(invocation, &packet, |index, protocol| {
                format!("{index}: {protocol}")
            })?;
        }
        None => {
            for (index, layer) in decoded.packet.iter().enumerate() {
                write_stdout_line(invocation, format_args!("{index}: {}", layer.protocol_id()))?;
            }
            render_dns_records(invocation, &packet)?;
            presentation.details(invocation, "Decoded fields", &packet)?;
        }
    }
    render_diagnostics_text(invocation, &decoded.diagnostics)
}

fn parse_hex_text(text: &str) -> Result<bytes::Bytes, CliError> {
    let bytes = core::layer::parse_hex(text.trim_start())
        .map_err(|source| CliError::caused(Kind::Usage, &source))?;
    if bytes.is_empty() {
        return Err(missing_input_error(InputKind::FrameHex));
    }
    Ok(bytes)
}

/// Decodes bounded hexadecimal text, keeping the decoded size inside the packet budget.
fn hex_frame_bytes(text: &[u8], max_packet_size: usize) -> Result<Vec<u8>, CliError> {
    if text.len() > hex_text_limit(max_packet_size) {
        return Err(CliError::from_classification(
            core::error::Classified::classification(&core::decode::Error::PacketSizeLimit {
                actual: text.len(),
                limit: max_packet_size,
            }),
            format!(
                "frame hex text input exceeds {} byte limit",
                hex_text_limit(max_packet_size)
            ),
            Vec::new(),
        ));
    }
    let text =
        std::str::from_utf8(text).map_err(|source| CliError::caused(Kind::Usage, &source))?;
    let trimmed = text.trim_start();
    let digits = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    // Count the same bytes the parser retains before it allocates its compact
    // string and decoded buffer. Round up so an extra nibble also respects the budget.
    let actual = digits
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace() && !matches!(*byte, b':' | b'-'))
        .count()
        .div_ceil(2);
    if actual > max_packet_size {
        return Err(CliError::classified(core::decode::Error::PacketSizeLimit {
            actual,
            limit: max_packet_size,
        }));
    }
    let bytes = parse_hex_text(text)?;
    if bytes.len() > max_packet_size {
        return Err(CliError::classified(core::decode::Error::PacketSizeLimit {
            actual: bytes.len(),
            limit: max_packet_size,
        }));
    }
    Ok(bytes.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_hex_preserves_syntax_and_classifies_size_errors() {
        assert_eq!(
            hex_frame_bytes(b" \t0X00:ab-CD\n", 3).unwrap(),
            [0, 0xab, 0xcd]
        );
        let error = hex_frame_bytes(b"00:ab:cd:ef", 3).unwrap_err();
        assert_eq!(error.classification.code, "policy.decode_resource_limit");
        assert_eq!(error.classification.kind, Kind::Policy);
        assert_eq!(
            error.message,
            "captured packet size 4 exceeds configured limit 3"
        );
        for value in [b"00f".as_slice(), b"zz", &[0xff]] {
            assert_eq!(
                hex_frame_bytes(value, 8).unwrap_err().classification.kind,
                Kind::Usage
            );
        }
        assert!(
            hex_frame_bytes(b" \t", 3)
                .unwrap_err()
                .message
                .contains("required")
        );
    }

    #[test]
    fn bounded_hex_rejects_oversized_text_and_extra_nibbles() {
        let mut oversized = b"00".to_vec();
        oversized.resize(hex_text_limit(1) + 1, b' ');
        let error = hex_frame_bytes(&oversized, 1).unwrap_err();
        assert_eq!(error.classification.code, "policy.decode_resource_limit");
        assert_eq!(error.classification.kind, Kind::Policy);
        assert!(error.message.starts_with("frame hex text input exceeds"));
        let error = hex_frame_bytes(b"aabbc", 2).unwrap_err();
        assert_eq!(error.classification.kind, Kind::Policy);
    }
}
