// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::super::expression::decode_hex;
use super::super::field::FieldKind;
use super::super::layer::{FieldSchema, LayerSchema, ProtocolId};
use super::super::registry::ProtocolRegistry;
use super::ast::{Node, Operand, Operator};
use super::error::FilterError;
use super::lexer::{Token, TokenKind};

pub(super) struct Compiler<'a> {
    tokens: &'a [Token],
    index: usize,
    registry: &'a ProtocolRegistry,
    max_nesting: usize,
    end_offset: usize,
}

impl<'a> Compiler<'a> {
    pub(super) fn new(
        tokens: &'a [Token],
        registry: &'a ProtocolRegistry,
        max_nesting: usize,
        end_offset: usize,
    ) -> Self {
        Self {
            tokens,
            index: 0,
            registry,
            max_nesting,
            end_offset,
        }
    }

    pub(super) fn compile(mut self) -> Result<Node, FilterError> {
        let node = self.parse_or(0)?;
        match self.peek() {
            None => Ok(node),
            Some(token) => Err(FilterError::Syntax {
                offset: token.offset,
                message: "trailing input after the complete filter".to_owned(),
            }),
        }
    }

    fn parse_or(&mut self, depth: usize) -> Result<Node, FilterError> {
        let mut node = self.parse_and(depth)?;
        while matches!(self.peek().map(|token| &token.kind), Some(TokenKind::Or)) {
            self.index += 1;
            let right = self.parse_and(depth)?;
            node = Node::Or(Box::new(node), Box::new(right));
        }
        Ok(node)
    }

    fn parse_and(&mut self, depth: usize) -> Result<Node, FilterError> {
        let mut node = self.parse_unary(depth)?;
        while matches!(self.peek().map(|token| &token.kind), Some(TokenKind::And)) {
            self.index += 1;
            let right = self.parse_unary(depth)?;
            node = Node::And(Box::new(node), Box::new(right));
        }
        Ok(node)
    }

    fn parse_unary(&mut self, depth: usize) -> Result<Node, FilterError> {
        if matches!(self.peek().map(|token| &token.kind), Some(TokenKind::Not)) {
            self.index += 1;
            // Negation recurses, so it consumes nesting budget exactly like a
            // parenthesized group.
            let depth = self.deeper(depth)?;
            return Ok(Node::Not(Box::new(self.parse_unary(depth)?)));
        }
        self.parse_primary(depth)
    }

    fn parse_primary(&mut self, depth: usize) -> Result<Node, FilterError> {
        let token = self.next_token()?;
        match &token.kind {
            TokenKind::OpenParen => {
                let depth = self.deeper(depth)?;
                let node = self.parse_or(depth)?;
                let close = self.next_token()?;
                if close.kind != TokenKind::CloseParen {
                    return Err(FilterError::Syntax {
                        offset: close.offset,
                        message: "expected a closing parenthesis".to_owned(),
                    });
                }
                Ok(node)
            }
            TokenKind::Path(path) => self.parse_predicate(token.offset, path),
            _ => Err(FilterError::Syntax {
                offset: token.offset,
                message: "expected a protocol name, a field comparison, or a group".to_owned(),
            }),
        }
    }

    fn parse_predicate(&mut self, offset: usize, path: &str) -> Result<Node, FilterError> {
        let (protocol_name, field_name) = match path.split_once('.') {
            Some((protocol, field)) => (protocol, Some(field)),
            None => (path, None),
        };
        if protocol_name.is_empty() {
            return Err(FilterError::Syntax {
                offset,
                message: "expected a protocol name before the field".to_owned(),
            });
        }
        let protocol = self
            .registry
            .protocol_named(protocol_name)
            .ok_or_else(|| FilterError::UnknownProtocol {
                offset,
                name: protocol_name.to_owned(),
            })?
            .clone();

        let Some(field_name) = field_name else {
            if matches!(
                self.peek().map(|token| &token.kind),
                Some(TokenKind::Operator(_))
            ) {
                return Err(FilterError::Syntax {
                    offset,
                    message: format!(
                        "{protocol_name} is a protocol; compare one of its fields as {protocol_name}.FIELD"
                    ),
                });
            }
            return Ok(Node::Presence { protocol });
        };
        if field_name.is_empty() || field_name.contains('.') {
            return Err(FilterError::Syntax {
                offset,
                message: "expected exactly one PROTOCOL.FIELD path".to_owned(),
            });
        }

        let schema = self.layer_schema(offset, &protocol)?;
        let field = schema
            .fields
            .iter()
            .find(|field| field.name == field_name)
            .ok_or_else(|| FilterError::UnknownField {
                offset,
                protocol: protocol.as_str().to_owned(),
                field: field_name.to_owned(),
                available: schema
                    .fields
                    .iter()
                    .map(|field| field.name.to_owned())
                    .collect(),
            })?;

        let (operator, operand) = self.parse_comparison(&protocol, field)?;
        Ok(Node::Compare {
            protocol,
            field: field.name,
            operator,
            operand,
        })
    }

    fn parse_comparison(
        &mut self,
        protocol: &ProtocolId,
        field: &FieldSchema,
    ) -> Result<(Operator, Operand), FilterError> {
        let token = self.next_token()?;
        let TokenKind::Operator(operator) = token.kind else {
            return Err(FilterError::Syntax {
                offset: token.offset,
                message: format!(
                    "expected a comparison operator after {}.{}",
                    protocol, field.name
                ),
            });
        };
        let value = self.next_token()?;
        let TokenKind::Value(literal) = &value.kind else {
            return Err(FilterError::Syntax {
                offset: value.offset,
                message: "expected a literal value".to_owned(),
            });
        };
        if operator.is_ordering() && !matches!(field.kind, FieldKind::Unsigned | FieldKind::Signed)
        {
            return Err(FilterError::UnorderedField {
                offset: token.offset,
                protocol: protocol.as_str().to_owned(),
                field: field.name.to_owned(),
                kind: field.kind,
            });
        }
        let operand = parse_operand(value.offset, protocol, field, literal, operator)?;
        Ok((operator, operand))
    }

    /// Resolves the reflective schema a protocol exposes.
    ///
    /// A codec describes its fields through a constructed layer, so a
    /// decode-only codec that cannot construct one has no schema to validate
    /// against. Its presence can still be tested.
    fn layer_schema(
        &self,
        offset: usize,
        protocol: &ProtocolId,
    ) -> Result<&'static LayerSchema, FilterError> {
        self.registry
            .codec(protocol)
            .and_then(|codec| codec.make_layer(&BTreeMap::new()).ok())
            .map(|layer| layer.schema())
            .ok_or_else(|| FilterError::UnreflectiveProtocol {
                offset,
                protocol: protocol.as_str().to_owned(),
            })
    }

    fn deeper(&self, depth: usize) -> Result<usize, FilterError> {
        let depth = depth + 1;
        if depth > self.max_nesting {
            return Err(FilterError::NestingLimit {
                limit: self.max_nesting,
            });
        }
        Ok(depth)
    }

    fn peek(&self) -> Option<&Token> {
        self.tokens.get(self.index)
    }

    fn next_token(&mut self) -> Result<Token, FilterError> {
        let token = self
            .tokens
            .get(self.index)
            .cloned()
            .ok_or_else(|| FilterError::Syntax {
                offset: self.end_offset,
                message: "filter ended before the expression was complete".to_owned(),
            })?;
        self.index += 1;
        Ok(token)
    }
}

fn parse_operand(
    offset: usize,
    protocol: &ProtocolId,
    field: &FieldSchema,
    literal: &str,
    operator: Operator,
) -> Result<Operand, FilterError> {
    let mismatch = || FilterError::TypeMismatch {
        offset,
        protocol: protocol.as_str().to_owned(),
        field: field.name.to_owned(),
        kind: field.kind,
        literal: literal.to_owned(),
    };
    match field.kind {
        FieldKind::Bool => match literal {
            "true" => Ok(Operand::Bool(true)),
            "false" => Ok(Operand::Bool(false)),
            _ => Err(mismatch()),
        },
        FieldKind::Unsigned => parse_unsigned(literal)
            .map(Operand::Unsigned)
            .ok_or_else(mismatch),
        FieldKind::Signed => parse_signed(literal)
            .map(Operand::Signed)
            .ok_or_else(mismatch),
        FieldKind::Text => Ok(Operand::Text(literal.to_owned())),
        FieldKind::Bytes => decode_hex(literal)
            .map(Operand::Bytes)
            .map_err(|_| mismatch()),
        FieldKind::Ipv4 => parse_ipv4_operand(literal, operator).ok_or_else(mismatch),
        FieldKind::Ipv6 => parse_ipv6_operand(literal, operator).ok_or_else(mismatch),
        FieldKind::Mac => parse_mac(literal).map(Operand::Mac).ok_or_else(mismatch),
        FieldKind::List => Err(FilterError::UnfilterableField {
            offset,
            protocol: protocol.as_str().to_owned(),
            field: field.name.to_owned(),
        }),
        // `FieldKind` is non-exhaustive; an unknown kind has no literal syntax
        // this compiler can honor, so refuse rather than guess.
        #[allow(unreachable_patterns)]
        _ => Err(mismatch()),
    }
}

fn parse_unsigned(literal: &str) -> Option<u64> {
    match literal
        .strip_prefix("0x")
        .or_else(|| literal.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => literal.parse().ok(),
    }
}

fn parse_signed(literal: &str) -> Option<i64> {
    match literal
        .strip_prefix("0x")
        .or_else(|| literal.strip_prefix("0X"))
    {
        Some(hex) => i64::from_str_radix(hex, 16).ok(),
        None => literal.parse().ok(),
    }
}

fn parse_ipv4_operand(literal: &str, operator: Operator) -> Option<Operand> {
    let Some((address, prefix)) = literal.split_once('/') else {
        return literal.parse::<Ipv4Addr>().ok().map(Operand::Ipv4);
    };
    // A prefix describes a set, so only membership is meaningful.
    if operator.is_ordering() {
        return None;
    }
    let address = address.parse::<Ipv4Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok().filter(|prefix| *prefix <= 32)?;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    };
    Some(Operand::Ipv4Prefix {
        network: u32::from(address) & mask,
        mask,
    })
}

fn parse_ipv6_operand(literal: &str, operator: Operator) -> Option<Operand> {
    let Some((address, prefix)) = literal.split_once('/') else {
        return literal.parse::<Ipv6Addr>().ok().map(Operand::Ipv6);
    };
    if operator.is_ordering() {
        return None;
    }
    let address = address.parse::<Ipv6Addr>().ok()?;
    let prefix = prefix.parse::<u8>().ok().filter(|prefix| *prefix <= 128)?;
    let mask = if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    };
    Some(Operand::Ipv6Prefix {
        network: u128::from(address) & mask,
        mask,
    })
}

fn parse_mac(literal: &str) -> Option<[u8; 6]> {
    let separator = if literal.contains(':') { ':' } else { '-' };
    let mut address = [0_u8; 6];
    let mut parts = literal.split(separator);
    for octet in &mut address {
        *octet = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(address)
}
