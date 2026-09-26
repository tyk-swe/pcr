// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Bounded packet-set arguments shared by build and exchange.

use clap::Args;
use packetcraftr_core::{
    error::Kind,
    expression,
    field::FieldValue,
    packet::Packet,
    template::{DEFAULT_MAX_TEMPLATE_PACKETS, NumericRange, Template},
};

use crate::errors::CliError;

#[derive(Debug, Args)]
pub(crate) struct TemplateArgs {
    /// Vary a zero-based layer field over an expression list or an inclusive
    /// unsigned range, e.g. 0.ttl=[1,64] or 0.ttl=1..64:8. Repeat for a
    /// Cartesian product; the last axis varies fastest.
    #[arg(long = "axis", value_name = "LAYER.FIELD=[VALUES]|START..END[:STEP]")]
    // clap prints this doc comment verbatim as --help text, so it is not rustdoc markup.
    #[allow(rustdoc::broken_intra_doc_links)]
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

/// An axis operand whose size is known before its values are materialized.
enum AxisSource {
    List(Vec<FieldValue>),
    Range(NumericRange),
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
                    "--axis requires LAYER.FIELD=[VALUES] or LAYER.FIELD=START..END[:STEP] with a zero-based layer and a non-empty set",
                )
            };
            let (selector, values) = source.split_once('=').ok_or_else(syntax)?;
            let values = values.trim();
            let (layer, field) = selector.trim().split_once('.').ok_or_else(syntax)?;
            let layer = layer.parse::<usize>().map_err(|_| syntax())?;
            let field = field.trim().to_ascii_lowercase();
            if field.is_empty() {
                return Err(syntax());
            }
            // A bare START..END[:STEP] operand is a range; anything else must be
            // a bracketed expression list. Range lengths count arithmetically so
            // oversized spans fail on the ceiling before any value materializes.
            let (source, axis_len) = if values.starts_with('[') {
                let FieldValue::List(values) = expression::parse_value(values, options.clone())
                    .map_err(CliError::classified)?
                else {
                    return Err(syntax());
                };
                if values.is_empty() {
                    return Err(syntax());
                }
                let axis_len = values.len();
                (AxisSource::List(values), axis_len)
            } else {
                let range = parse_range(values)?;
                let axis_len = usize::try_from(range.len()).map_err(|_| {
                    CliError::classified(packetcraftr_core::template::Error::ExpansionOverflow)
                })?;
                (AxisSource::Range(range), axis_len)
            };
            // This boundary check precedes route preparation; the library
            // independently checks expansion for callers that bypass the CLI.
            count = count.checked_mul(axis_len).ok_or_else(|| {
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
            let values = match source {
                AxisSource::List(values) => values,
                AxisSource::Range(range) => range.values().collect(),
            };
            axes.push(Axis {
                layer,
                field,
                values,
            });
        }
        Ok(ParsedTemplate { axes })
    }
}

/// Parses a `START..END[:STEP]` axis operand. Endpoints and the step are
/// unsigned decimal or `0x`-prefixed integers; the range is inclusive,
/// ascending, and produces `FieldValue::Unsigned` values.
fn parse_range(text: &str) -> Result<NumericRange, CliError> {
    let syntax = || {
        CliError::new(
            Kind::Cli,
            "--axis range requires START..END[:STEP] with unsigned decimal or 0x-prefixed integers",
        )
    };
    let (start, rest) = text.split_once("..").ok_or_else(syntax)?;
    let (end, step) = rest
        .split_once(':')
        .map_or((rest, None), |(end, step)| (end, Some(step)));
    NumericRange::new(
        parse_unsigned(start.trim()).ok_or_else(syntax)?,
        parse_unsigned(end.trim()).ok_or_else(syntax)?,
        step.map_or(Ok(1), |step| parse_unsigned(step.trim()).ok_or_else(syntax))?,
    )
    .map_err(CliError::classified)
}

fn parse_unsigned(text: &str) -> Option<u64> {
    if let Some(hexadecimal) = text.strip_prefix("0x") {
        u64::from_str_radix(hexadecimal, 16).ok()
    } else {
        text.parse().ok()
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

    #[test]
    fn range_axes_expand_inclusively_and_mix_with_lists() {
        let parsed = TemplateArgs {
            axes: vec!["0.ttl=1..5:2".to_owned(), "1.dport=[80,443]".to_owned()],
            max_template_packets: 10,
        }
        .parse()
        .expect("mixed range and list axes parse");
        assert_eq!(parsed.axes.len(), 2);
        assert_eq!(
            parsed.axes[0].values,
            [
                FieldValue::Unsigned(1),
                FieldValue::Unsigned(3),
                FieldValue::Unsigned(5)
            ]
        );
        assert_eq!(
            parsed.axes[1].values,
            [FieldValue::Unsigned(80), FieldValue::Unsigned(443)]
        );
    }

    #[test]
    fn range_axes_count_arithmetically_before_materializing_values() {
        let error = TemplateArgs {
            axes: vec![format!("0.ttl=0..{}", u64::MAX)],
            max_template_packets: DEFAULT_MAX_TEMPLATE_PACKETS,
        }
        .parse()
        .err()
        .expect("an astronomical range fails on the ceiling, not on allocation");
        assert_eq!(error.classification.code, "cli.template_limit");
    }

    #[test]
    fn malformed_and_invalid_ranges_are_typed_failures() {
        for (source, code) in [
            ("0.ttl=1..5:0", "cli.template_range"),
            ("0.ttl=5..1", "cli.template_range"),
            ("0.ttl=1..", "cli.error"),
            ("0.ttl=..5", "cli.error"),
            ("0.ttl=-1..5", "cli.error"),
            ("0.ttl=1..5:", "cli.error"),
            ("0.ttl=1..5:2:3", "cli.error"),
            ("0.ttl=1..2..3", "cli.error"),
            ("0.ttl=abc", "cli.error"),
        ] {
            let error = TemplateArgs {
                axes: vec![source.to_owned()],
                max_template_packets: DEFAULT_MAX_TEMPLATE_PACKETS,
            }
            .parse()
            .err()
            .unwrap_or_else(|| panic!("{source} must fail"));
            assert_eq!(error.classification.code, code, "{source}");
        }
    }

    #[test]
    fn list_and_range_operands_accept_surrounding_whitespace() {
        for operand in [" [1, 2] ", " 1..2 "] {
            let parsed = TemplateArgs {
                axes: vec![format!("0.ttl={operand}")],
                max_template_packets: 2,
            }
            .parse()
            .unwrap();
            assert_eq!(parsed.axes[0].values, [1_u8.into(), 2_u8.into()]);
        }
    }
}
