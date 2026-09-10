// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded packet-set arguments shared by build and exchange.

use clap::Args;
use packetcraftr_core::{
    error::Kind,
    expression,
    field::FieldValue,
    packet::Packet,
    template::{DEFAULT_MAX_TEMPLATE_PACKETS, Template},
};

use crate::errors::CliError;

#[derive(Debug, Args)]
pub(crate) struct TemplateArgs {
    /// Vary a zero-based layer field over an expression list, e.g. 0.ttl=[1,64].
    /// Repeat for a Cartesian product; the last axis varies fastest.
    #[arg(long = "axis", value_name = "LAYER.FIELD=[VALUES]")]
    pub(crate) axes: Vec<String>,
    /// Maximum packets in the complete Cartesian product, checked before preparation.
    #[arg(long, default_value_t = DEFAULT_MAX_TEMPLATE_PACKETS)]
    pub(crate) max_template_packets: usize,
}

struct Axis {
    layer: usize,
    field: String,
    values: Vec<FieldValue>,
}

pub(crate) struct ParsedTemplate {
    axes: Vec<Axis>,
}

impl TemplateArgs {
    /// Check syntax, aggregate input size, and the complete expansion ceiling
    /// before a caller reads its recipe or performs route preparation.
    pub(crate) fn parse(self) -> Result<ParsedTemplate, CliError> {
        let maximum = self.max_template_packets;
        if maximum == 0 {
            return Err(CliError::new(
                Kind::Cli,
                "--max-template-packets must be non-zero",
            ));
        }
        let options = expression::Options::default();
        let mut bytes = 0_usize;
        for axis in &self.axes {
            bytes = bytes.saturating_add(axis.len());
            if bytes > options.max_bytes {
                return Err(CliError::classified(expression::Error::SizeLimit {
                    actual: bytes,
                    limit: options.max_bytes,
                }));
            }
        }
        let mut axes = Vec::new();
        let mut count = 1_usize;
        for source in self.axes {
            let syntax = || {
                CliError::new(
                    Kind::Cli,
                    "--axis requires LAYER.FIELD=[VALUES] with a zero-based layer and a non-empty list",
                )
            };
            let (selector, values) = source.split_once('=').ok_or_else(syntax)?;
            let (layer, field) = selector.trim().split_once('.').ok_or_else(syntax)?;
            let layer = layer.parse::<usize>().map_err(|_| syntax())?;
            let field = field.trim().to_ascii_lowercase();
            if field.is_empty() {
                return Err(syntax());
            }
            let FieldValue::List(values) =
                expression::parse_value(values, options.clone()).map_err(CliError::classified)?
            else {
                return Err(syntax());
            };
            if values.is_empty() {
                return Err(syntax());
            }
            // This boundary check precedes route preparation; the library
            // independently checks expansion for callers that bypass the CLI.
            count = count.checked_mul(values.len()).ok_or_else(|| {
                CliError::classified(packetcraftr_core::template::Error::ExpansionOverflow)
            })?;
            if count > maximum {
                return Err(CliError::classified(
                    packetcraftr_core::template::Error::ExpansionLimit {
                        requested: count,
                        limit: maximum,
                    },
                ));
            }
            axes.push(Axis {
                layer,
                field,
                values,
            });
        }
        Ok(ParsedTemplate { axes })
    }
}

impl ParsedTemplate {
    pub(crate) fn into_template(self, base: Packet) -> Template {
        let mut template = Template::new(base);
        for axis in self.axes {
            template = template.axis(axis.layer, axis.field, axis.values);
        }
        template
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn axes_share_the_input_byte_ceiling_before_parsing_any_values() {
        let half = expression::Options::default().max_bytes / 2;
        let source = format!("0.label=[\"{}\"]", "x".repeat(half));
        let error = TemplateArgs {
            axes: vec![source.clone(), source],
            max_template_packets: 1,
        }
        .parse()
        .err()
        .expect("combined axes exceed the byte ceiling");
        assert_eq!(error.classification.code, "cli.expression_limit");
    }
}
