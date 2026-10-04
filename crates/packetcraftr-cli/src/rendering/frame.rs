// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::fmt::{self, Write as _};
use std::sync::Arc;

use packetcraftr_core::document;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::field::FieldValue;
use packetcraftr_core::layer::FieldSchema;
use packetcraftr_core::registry::Registry;

use crate::errors::CliError;
use crate::output;

use super::style::terminal_safe;
use super::{
    push_stdout_line, render_diagnostics_text, render_dns_records, spaced_hex, write_stdout_block,
    write_stdout_line,
};

/// Registered decoders nest far less; this is the document nesting ceiling.
const MAX_TREE_DEPTH: usize = document::MAX_DOCUMENT_NESTING;

pub(crate) fn render_frame_text(
    source_frame: output::frame::SourceFrame,
    frame: &output::frame::Captured,
    decoded: Option<&output::frame::Stack>,
) -> Result<(), CliError> {
    render_frame(source_frame, frame, decoded, None)
}

/// As [`render_frame_text`], listing each layer's fields in place of the DNS summary lines.
pub(crate) fn render_frame_tree(
    source_frame: output::frame::SourceFrame,
    frame: &output::frame::Captured,
    decoded: Option<&output::frame::Stack>,
    tree: &mut FieldTree,
) -> Result<(), CliError> {
    render_frame(source_frame, frame, decoded, Some(tree))
}

fn render_frame(
    source_frame: output::frame::SourceFrame,
    frame: &output::frame::Captured,
    decoded: Option<&output::frame::Stack>,
    tree: Option<&mut FieldTree>,
) -> Result<(), CliError> {
    match decoded {
        None => write_stdout_line(format_args!(
            "{source_frame}: {}",
            captured_frame_text(frame)
        )),
        Some(decoded) => {
            write_stdout_line(format_args!(
                "{source_frame}: dlt={} caplen={} wirelen={} layers={} {}",
                frame.link_type,
                frame.captured_length,
                frame.original_length,
                decoded
                    .packet
                    .layers
                    .iter()
                    .map(|layer| layer.protocol.as_str())
                    .collect::<Vec<_>>()
                    .join("/"),
                spaced_hex(frame.bytes())
            ))?;
            match tree {
                Some(tree) => tree.render_layers(&decoded.packet, |index, protocol| {
                    format!("{source_frame}: {index}: {protocol}")
                })?,
                None => render_dns_records(&decoded.packet)?,
            }
            if !decoded.diagnostics.is_empty() {
                write_stdout_line(format_args!("{source_frame}: diagnostics:"))?;
                render_diagnostics_text(&decoded.diagnostics)?;
            }
            Ok(())
        }
    }
}

/// Streams each layer's fields as an indented tree while charging every line to a byte budget.
pub(crate) struct FieldTree {
    registry: Arc<Registry>,
    remaining: usize,
}

/// What the registry schema says about the field being printed.
#[derive(Clone, Copy)]
struct Scope<'a> {
    derived: bool,
    children: &'a [FieldSchema],
}

type Emit<'a> = dyn FnMut(&str) -> Result<(), CliError> + 'a;

impl FieldTree {
    pub(crate) fn new(registry: Arc<Registry>, max_bytes: usize) -> Self {
        Self {
            registry,
            remaining: max_bytes,
        }
    }

    /// Prints `header(index, protocol)` and then the layer's fields for every layer.
    ///
    /// `(derived)` marks fields the protocol schema defines as derivable, such as lengths and
    /// checksums; the values shown are always the decoded wire values.
    pub(crate) fn render_layers(
        &mut self,
        packet: &document::Packet,
        header: impl Fn(usize, &str) -> String,
    ) -> Result<(), CliError> {
        // One write per packet; lines rendered before a failure are still written.
        let mut block = String::new();
        let walked = self.walk(packet, &header, &mut |line| {
            push_stdout_line(&mut block, format_args!("{line}"));
            Ok(())
        });
        write_stdout_block(&block)?;
        walked
    }

    fn walk(
        &mut self,
        packet: &document::Packet,
        header: &dyn Fn(usize, &str) -> String,
        emit: &mut Emit<'_>,
    ) -> Result<(), CliError> {
        let registry = Arc::clone(&self.registry);
        for (index, layer) in packet.layers.iter().enumerate() {
            self.line(&header(index, &layer.protocol), emit)?;
            let schema = registry
                .schema(&layer.protocol)
                .map_or(&[][..], |schema| schema.fields);
            // Schema order is the protocol's wire order; the document's map is alphabetical.
            let mut fields: Vec<_> = layer.fields.iter().collect();
            fields.sort_by_key(|(name, _)| {
                schema
                    .iter()
                    .position(|field| field.name == name.as_str())
                    .unwrap_or(usize::MAX)
            });
            for (name, value) in fields {
                let scope = schema
                    .iter()
                    .find(|field| field.name == name)
                    .map_or(Scope::UNKNOWN, Scope::of);
                self.field(name, value, scope, 1, emit)?;
            }
        }
        Ok(())
    }

    fn field(
        &mut self,
        label: &str,
        value: &FieldValue,
        scope: Scope<'_>,
        depth: usize,
        emit: &mut Emit<'_>,
    ) -> Result<(), CliError> {
        if depth > MAX_TREE_DEPTH {
            return Err(limit_error(format!(
                "field tree nests deeper than {MAX_TREE_DEPTH} levels"
            )));
        }
        let indent = "  ".repeat(depth);
        let marker = if scope.derived { " (derived)" } else { "" };
        match value {
            FieldValue::List(items) if !items.is_empty() => {
                self.line(&format!("{indent}{label}:{marker}"), emit)?;
                let item_scope = Scope {
                    derived: false,
                    children: scope.children,
                };
                for (index, item) in items.iter().enumerate() {
                    self.field(&format!("[{index}]"), item, item_scope, depth + 1, emit)?;
                }
                Ok(())
            }
            FieldValue::Object(members) if !members.is_empty() => {
                self.line(&format!("{indent}{label}:{marker}"), emit)?;
                for (name, member) in members {
                    let member_scope = scope
                        .children
                        .iter()
                        .find(|field| field.name == name)
                        .map_or(Scope::UNKNOWN, Scope::of);
                    self.field(name, member, member_scope, depth + 1, emit)?;
                }
                Ok(())
            }
            scalar => {
                if let FieldValue::Bytes(bytes) = scalar {
                    // The hex rendering costs two characters per byte; refuse
                    // before allocating it when the budget cannot carry it.
                    if self.remaining < bytes.len().saturating_mul(2) {
                        return Err(limit_error(
                            "field tree output exceeds --max-tree-bytes".to_owned(),
                        ));
                    }
                }
                let text = scalar_text(scalar);
                self.line(&format!("{indent}{label} = {text}{marker}"), emit)
            }
        }
    }

    /// Charges the escaped line and its newline before it is emitted.
    fn line(&mut self, text: &str, emit: &mut Emit<'_>) -> Result<(), CliError> {
        let safe = terminal_safe(text);
        self.remaining = safe
            .len()
            .checked_add(1)
            .and_then(|cost| self.remaining.checked_sub(cost))
            .ok_or_else(|| limit_error("field tree output exceeds --max-tree-bytes".to_owned()))?;
        emit(&safe)
    }
}

fn limit_error(message: String) -> CliError {
    CliError::from_classification(
        Classification::new(
            "policy.tree_output_limit",
            Kind::Policy,
            Some("select fewer frames or deliberately raise --max-tree-bytes"),
        ),
        message,
        Vec::new(),
    )
}

impl Scope<'_> {
    const UNKNOWN: Scope<'static> = Scope {
        derived: false,
        children: &[],
    };

    fn of(field: &FieldSchema) -> Scope<'_> {
        Scope {
            derived: field.derived,
            children: field.children,
        }
    }
}

/// Scalars print inline; empty lists and objects print as `[]` and `{}`, bytes with their count.
fn scalar_text(value: &FieldValue) -> String {
    match value {
        FieldValue::Bool(value) => value.to_string(),
        FieldValue::Unsigned(value) => value.to_string(),
        FieldValue::Signed(value) => value.to_string(),
        FieldValue::Text(value) => format!("{value:?}"),
        FieldValue::Bytes(bytes) => {
            let count = bytes.len();
            let unit = if count == 1 { "byte" } else { "bytes" };
            if count == 0 {
                return format!("({count} {unit})");
            }
            let mut text = String::with_capacity(count.saturating_mul(2).saturating_add(16));
            for byte in bytes.iter() {
                let _ = write!(text, "{byte:02x}");
            }
            let _ = write!(text, " ({count} {unit})");
            text
        }
        FieldValue::Ipv4(address) => address.to_string(),
        FieldValue::Ipv6(address) => address.to_string(),
        FieldValue::Mac([a, b, c, d, e, f]) => {
            format!("{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{f:02x}")
        }
        FieldValue::List(_) => "[]".to_owned(),
        FieldValue::Object(_) => "{}".to_owned(),
        // `FieldValue` is non-exhaustive; a future kind must not print as nothing.
        _ => "<unprintable>".to_owned(),
    }
}

pub(crate) fn render_undecoded<'a>(
    rows: impl IntoIterator<Item = (Option<String>, &'a output::frame::Captured)>,
) -> Result<(), CliError> {
    for (label, frame) in rows {
        match label {
            Some(label) => write_stdout_line(format_args!(
                "undecoded {label} {}",
                captured_frame_text(frame)
            ))?,
            None => write_stdout_line(format_args!("undecoded {}", captured_frame_text(frame)))?,
        }
    }
    Ok(())
}

pub(crate) fn captured_frame_text(frame: &output::frame::Captured) -> impl fmt::Display + '_ {
    CapturedFrameText(frame)
}

struct CapturedFrameText<'a>(&'a output::frame::Captured);

impl fmt::Display for CapturedFrameText<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let frame = self.0;
        write!(
            formatter,
            "dlt={} caplen={} wirelen={} {}",
            frame.link_type,
            frame.captured_length,
            frame.original_length,
            spaced_hex(frame.bytes())
        )
    }
}

#[cfg(test)]
mod tests {

    use bytes::Bytes;
    use packetcraftr_core::protocol::builtin;

    use super::*;

    fn packet(protocol: &str, fields: Vec<(&str, FieldValue)>) -> document::Packet {
        document::Packet {
            schema: document::PACKET_DOCUMENT_SCHEMA_V2.to_owned(),
            layers: vec![document::Layer {
                protocol: protocol.to_owned(),
                fields: fields
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value))
                    .collect(),
            }],
        }
    }

    fn lines(packet: &document::Packet, budget: usize) -> Result<Vec<String>, CliError> {
        let mut tree = FieldTree::new(builtin::registry(), budget);
        let mut lines = Vec::new();
        tree.walk(
            packet,
            &|index, protocol| format!("{index}: {protocol}"),
            &mut |line| {
                lines.push(line.to_owned());
                Ok(())
            },
        )?;
        Ok(lines)
    }

    #[test]
    fn exhausting_the_budget_is_a_typed_policy_error() {
        let packet = packet("ipv4", vec![("ttl", FieldValue::Unsigned(64))]);
        let error = lines(&packet, 0).unwrap_err();
        assert_eq!(error.classification.code, "policy.tree_output_limit");
        assert_eq!(error.exit_code(), 6);
        // "0: ipv4" and "  ttl = 64" with their newlines.
        assert_eq!(lines(&packet, 8 + 11).unwrap().len(), 2);
        assert!(lines(&packet, 8 + 10).is_err());
    }

    #[test]
    fn a_byte_field_too_large_for_the_budget_is_refused_before_rendering() {
        let packet = packet(
            "ipv4",
            vec![(
                "options",
                FieldValue::Bytes(Bytes::from_static(&[0xab; 64])),
            )],
        );
        // "0: ipv4" leaves 5; the field's 128-character hex dump cannot fit.
        let error = lines(&packet, 13).unwrap_err();
        assert_eq!(error.classification.code, "policy.tree_output_limit");
    }
}
