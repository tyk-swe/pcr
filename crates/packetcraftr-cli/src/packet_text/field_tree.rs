// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::sync::Arc;

use packetcraftr_core::document;
use packetcraftr_core::error::{Classification, Kind};
use packetcraftr_core::field;
use packetcraftr_core::layer::FieldSchema;
use packetcraftr_core::registry::Registry;

use crate::errors::CliError;

use crate::terminal::{push_stdout_line, terminal_safe, write_stdout_block};

/// Registered decoders nest far less; this is the document nesting ceiling.
const MAX_TREE_DEPTH: usize = document::MAX_DOCUMENT_NESTING;

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
        invocation: &crate::invocation::Invocation,
        packet: &document::Packet,
        header: impl Fn(usize, &str) -> String,
    ) -> Result<(), CliError> {
        // One write per packet; lines rendered before a failure are still written.
        let mut block = String::new();
        let walked = self.walk(packet, &header, &mut |line| {
            push_stdout_line(&mut block, line);
            Ok(())
        });
        write_stdout_block(invocation, &block)?;
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
        value: &field::Value,
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
            field::Value::List(items) if !items.is_empty() => {
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
            field::Value::Object(members) if !members.is_empty() => {
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
                if let field::Value::Bytes(bytes) = scalar {
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
            packetcraftr_core::error::Code::PolicyTreeOutputLimit,
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
fn scalar_text(value: &field::Value) -> String {
    match value {
        field::Value::Bool(value) => value.to_string(),
        field::Value::Unsigned(value) => value.to_string(),
        field::Value::Signed(value) => value.to_string(),
        field::Value::Text(value) => format!("{value:?}"),
        field::Value::Bytes(bytes) => {
            let count = bytes.len();
            let unit = if count == 1 { "byte" } else { "bytes" };
            if count == 0 {
                return format!("({count} {unit})");
            }
            format!("{} ({count} {unit})", crate::output::hex::CompactHex(bytes))
        }
        field::Value::Ipv4(address) => address.to_string(),
        field::Value::Ipv6(address) => address.to_string(),
        field::Value::Mac(mac) => packetcraftr_core::packet::MacAddress(*mac).to_string(),
        field::Value::List(_) => "[]".to_owned(),
        field::Value::Object(_) => "{}".to_owned(),
        // `field::Value` is non-exhaustive; a future kind must not print as nothing.
        _ => "<unprintable>".to_owned(),
    }
}
