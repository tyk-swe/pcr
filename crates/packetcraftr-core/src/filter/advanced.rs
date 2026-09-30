// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use regex_automata::{meta::Regex, util::syntax::Config as RegexSyntax};

use super::{
    ast, comparison, eval,
    lexer::{CompareOperator, Spanned, Token},
    literal::Literal,
    parser::{self, Limits, Requirements, Subject},
    path::{self, FieldRef},
};
use crate::{
    field::{FieldKind, FieldValue},
    registry::Registry,
};

pub(super) const MAX_PATTERN_BYTES: usize = 8192;
pub(super) const MAX_COMPILED_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug)]
enum Function {
    Len,
    Count,
    Lower,
    Upper,
}
#[derive(Clone, Debug)]
enum Operand {
    Field(FieldRef),
    Function(Function, Box<Self>),
    Literal(Literal),
}
#[derive(Clone, Debug)]
enum Operation {
    Compare(CompareOperator),
    Regex(Regex),
    StartsWith,
    EndsWith,
}
#[derive(Clone, Debug)]
pub(super) struct Predicate {
    left: Operand,
    right: Operand,
    operation: Operation,
    all: bool,
}

impl Predicate {
    pub(super) fn compiled_storage(&self) -> usize {
        match &self.operation {
            Operation::Regex(regex) => regex
                .memory_usage()
                .saturating_add(std::mem::size_of::<Regex>()),
            _ => 0,
        }
    }
}

fn syntax(offset: usize, message: impl Into<String>) -> super::Error {
    super::Error::Syntax {
        offset,
        message: message.into(),
    }
}
fn function(word: &str) -> Option<Function> {
    match word {
        "len" => Some(Function::Len),
        "count" => Some(Function::Count),
        "lower" => Some(Function::Lower),
        "upper" => Some(Function::Upper),
        _ => None,
    }
}
fn operand(
    tokens: &[Spanned],
    start: usize,
    registry: &Registry,
    limits: &Limits,
    requirements: &mut Requirements,
    depth: usize,
) -> Result<(Operand, usize), super::Error> {
    if depth > limits.max_nesting {
        return Err(super::Error::NestingLimit {
            limit: limits.max_nesting,
        });
    }
    let Some(current) = tokens.get(start) else {
        return Err(syntax(0, "expected an operand"));
    };
    if let Token::Word(word) = &current.token {
        if let Some(func) = function(word) {
            if !matches!(
                tokens.get(start + 1).map(|t| &t.token),
                Some(Token::LeftParen)
            ) {
                return Err(syntax(current.offset, "function requires `(`"));
            }
            let (inner, next) =
                operand(tokens, start + 2, registry, limits, requirements, depth + 1)?;
            if !matches!(tokens.get(next).map(|t| &t.token), Some(Token::RightParen)) {
                return Err(syntax(current.offset, "function requires `)`"));
            }
            let kinds = kinds(&inner);
            let supported = match func {
                Function::Count => true,
                Function::Len => kinds.iter().all(|kind| {
                    matches!(
                        kind,
                        FieldKind::Text | FieldKind::Bytes | FieldKind::Mac | FieldKind::List
                    )
                }),
                Function::Lower | Function::Upper => kinds
                    .iter()
                    .all(|kind| matches!(kind, FieldKind::Text | FieldKind::Bytes)),
            };
            if !supported {
                return Err(syntax(
                    current.offset,
                    "function operand has an incompatible type",
                ));
            }
            return Ok((Operand::Function(func, Box::new(inner)), next + 1));
        }
        if let Some(literal) = super::literal::parse(word) {
            return Ok((Operand::Literal(literal), start + 1));
        }
        match parser::parse_subject(tokens, start, registry) {
            Ok(Subject::Field {
                mut field,
                mut index,
            }) => {
                if let Some(Spanned {
                    token: Token::Slice(contents),
                    offset,
                }) = tokens.get(index)
                {
                    path::attach_slice(&mut field, contents, *offset)?;
                    index += 1;
                }
                parser::record_requirements(&field, requirements);
                return Ok((Operand::Field(field), index));
            }
            Ok(Subject::Predicate(_, _)) => {
                return Err(syntax(current.offset, "operand names a layer, not a field"));
            }
            Err(error) if word.contains('.') => return Err(error),
            Err(_) => return Ok((Operand::Literal(Literal::Text(word.clone())), start + 1)),
        }
    }
    if let Token::Text(text) = &current.token {
        return Ok((Operand::Literal(Literal::Text(text.clone())), start + 1));
    }
    Err(syntax(
        current.offset,
        "expected a field, function or literal",
    ))
}
fn kinds(operand: &Operand) -> Vec<FieldKind> {
    match operand {
        Operand::Field(field) => field.specs.iter().map(|spec| spec.kind).collect(),
        Operand::Function(Function::Len | Function::Count, _) => vec![FieldKind::Unsigned],
        Operand::Function(_, inner) => kinds(inner),
        Operand::Literal(literal) => vec![literal_value(literal).kind()],
    }
}
fn compatible(left: &Operand, right: &Operand) -> bool {
    if let (Operand::Field(field), Operand::Literal(literal)) = (left, right) {
        return field.specs.is_empty()
            || field
                .specs
                .iter()
                .any(|spec| super::literal::compatible(*spec, literal));
    }
    let left = kinds(left);
    let right = kinds(right);
    left.is_empty()
        || right.is_empty()
        || left.iter().any(|l| {
            right.iter().any(|r| {
                l == r
                    || matches!(
                        (l, r),
                        (FieldKind::Unsigned, FieldKind::Signed)
                            | (FieldKind::Signed, FieldKind::Unsigned)
                            | (FieldKind::Bytes, FieldKind::Text)
                            | (FieldKind::Text, FieldKind::Bytes)
                            | (FieldKind::Bytes, FieldKind::Mac)
                            | (FieldKind::Mac, FieldKind::Bytes)
                            | (FieldKind::Bool, FieldKind::Unsigned)
                            | (FieldKind::List, _)
                            | (_, FieldKind::List)
                    )
            })
        })
}

pub(super) fn parse(
    tokens: &[Spanned],
    start: usize,
    registry: &Registry,
    limits: &Limits,
    requirements: &mut Requirements,
) -> Result<Option<(ast::Predicate, usize)>, super::Error> {
    let Token::Word(word) = &tokens[start].token else {
        return Ok(None);
    };
    let quantifier = matches!(word.as_str(), "any" | "all");
    let functional =
        function(word).is_some() || matches!(word.as_str(), "starts_with" | "ends_with");
    // Keep legacy literal spellings and diagnostics on the established path.
    let advanced_operator = tokens[start..].iter().take_while(|t| !matches!(t.token, Token::And | Token::Or))
        .any(|t| matches!(&t.token, Token::Word(s) if matches!(s.as_str(), "matches" | "starts_with" | "ends_with")));
    let field_rhs = tokens[start..]
        .windows(2)
        .take_while(|pair| !matches!(pair[0].token, Token::And | Token::Or))
        .any(|pair| {
            if !matches!(pair[0].token, Token::Compare(_)) {
                return false;
            }
            let Token::Word(word) = &pair[1].token else {
                return false;
            };
            function(word).is_some()
                || matches!(
                    path::resolve(word, registry, pair[1].offset),
                    Ok(path::Resolved::Field(_))
                )
        });
    if !quantifier && !functional && !advanced_operator && !field_rhs {
        return Ok(None);
    }
    let all = word == "all";
    let index = start + usize::from(quantifier);
    let predicate_function = tokens
        .get(index)
        .and_then(|t| {
            if let Token::Word(s) = &t.token {
                Some(s.as_str())
            } else {
                None
            }
        })
        .filter(|s| matches!(*s, "starts_with" | "ends_with"));
    let (left, right, operation, next) = if let Some(name) = predicate_function {
        if !matches!(
            tokens.get(index + 1).map(|t| &t.token),
            Some(Token::LeftParen)
        ) {
            return Err(syntax(
                tokens[index].offset,
                "predicate function requires `(`",
            ));
        }
        let (left, comma) = operand(tokens, index + 2, registry, limits, requirements, 0)?;
        if !matches!(tokens.get(comma).map(|t| &t.token), Some(Token::Comma)) {
            return Err(syntax(
                tokens[index].offset,
                "predicate function requires two operands",
            ));
        }
        let (right, close) = operand(tokens, comma + 1, registry, limits, requirements, 0)?;
        if !matches!(tokens.get(close).map(|t| &t.token), Some(Token::RightParen)) {
            return Err(syntax(
                tokens[index].offset,
                "predicate function requires `)`",
            ));
        }
        (
            left,
            right,
            if name == "starts_with" {
                Operation::StartsWith
            } else {
                Operation::EndsWith
            },
            close + 1,
        )
    } else {
        let (left, op_index) = operand(tokens, index, registry, limits, requirements, 0)?;
        let op = tokens
            .get(op_index)
            .ok_or_else(|| syntax(tokens[index].offset, "comparison requires an operator"))?;
        let operation = match &op.token {
            Token::Compare(operator) => Operation::Compare(*operator),
            Token::Word(name) if name == "matches" => {
                let Some(Spanned {
                    token: Token::Text(pattern),
                    ..
                }) = tokens.get(op_index + 1)
                else {
                    return Err(syntax(op.offset, "matches requires a quoted regex pattern"));
                };
                if pattern.len() > MAX_PATTERN_BYTES {
                    return Err(syntax(op.offset, "regex exceeds 8192 pattern bytes"));
                }
                let allowance = MAX_COMPILED_BYTES;
                let regex = Regex::builder()
                    .configure(
                        Regex::config()
                            .utf8_empty(false)
                            .nfa_size_limit(Some(allowance))
                            .dfa_size_limit(Some(allowance / 4))
                            .onepass_size_limit(Some(allowance / 4))
                            .hybrid_cache_capacity(allowance / 4),
                    )
                    .syntax(RegexSyntax::new().unicode(false).utf8(false))
                    .build(pattern)
                    .map_err(|error| {
                        syntax(op.offset, format!("invalid or oversized regex: {error}"))
                    })?;
                if regex
                    .memory_usage()
                    .saturating_add(std::mem::size_of::<Regex>())
                    > allowance
                {
                    return Err(syntax(
                        op.offset,
                        "regex exceeds compiled storage allowance",
                    ));
                }
                if kinds(&left).iter().any(|kind| {
                    !matches!(kind, FieldKind::Text | FieldKind::Bytes | FieldKind::List)
                }) {
                    return Err(syntax(op.offset, "matches requires text or bytes"));
                }
                let right = Operand::Literal(Literal::Text(pattern.clone()));
                return Ok(Some((
                    ast::Predicate::Advanced(Box::new(Predicate {
                        left,
                        right,
                        operation: Operation::Regex(regex),
                        all,
                    })),
                    op_index + 2,
                )));
            }
            Token::Word(name) if name == "starts_with" => Operation::StartsWith,
            Token::Word(name) if name == "ends_with" => Operation::EndsWith,
            _ => return Err(syntax(op.offset, "expected a comparison operator")),
        };
        let (right, next) = operand(tokens, op_index + 1, registry, limits, requirements, 0)?;
        (left, right, operation, next)
    };
    if !compatible(&left, &right) {
        return Err(syntax(
            tokens[start].offset,
            "comparison operands have incompatible types",
        ));
    }
    if !matches!(operation, Operation::Compare(_))
        && kinds(&left)
            .iter()
            .any(|kind| !matches!(kind, FieldKind::Text | FieldKind::Bytes | FieldKind::List))
    {
        return Err(syntax(
            tokens[start].offset,
            "text operation requires text or bytes",
        ));
    }
    if let (Operand::Field(field), Operand::Literal(literal)) = (&left, &right) {
        parser::check_literal(field, literal, tokens[start].offset)?;
        if literal.is_prefix()
            && matches!(operation,Operation::Compare(operator) if !matches!(operator,CompareOperator::Equal|CompareOperator::NotEqual))
        {
            return Err(super::Error::OrderedPrefixComparison {
                offset: tokens[start].offset,
                path: field.path.clone(),
                literal: literal.to_string(),
            });
        }
    }
    Ok(Some((
        ast::Predicate::Advanced(Box::new(Predicate {
            left,
            right,
            operation,
            all,
        })),
        next,
    )))
}
fn literal_value(literal: &Literal) -> FieldValue {
    match literal {
        Literal::Bool(v) => FieldValue::Bool(*v),
        Literal::Unsigned(v) => FieldValue::Unsigned(*v),
        Literal::Signed(v) => FieldValue::Signed(*v),
        Literal::Text(v) => FieldValue::Text(v.clone()),
        Literal::Bytes(v) => FieldValue::Bytes(v.clone()),
        Literal::Mac(v) => FieldValue::Mac(*v),
        Literal::Ipv4(v) | Literal::Ipv4Net(v, _) => FieldValue::Ipv4(*v),
        Literal::Ipv6(v) | Literal::Ipv6Net(v, _) => FieldValue::Ipv6(*v),
    }
}
fn flatten(value: FieldValue, output: &mut Vec<FieldValue>) {
    match value {
        FieldValue::List(values) => {
            for value in values {
                flatten(value, output);
            }
        }
        value => output.push(value),
    }
}
fn values(operand: &Operand, context: &eval::Context<'_>) -> Vec<FieldValue> {
    match operand {
        Operand::Literal(value) => vec![literal_value(value)],
        Operand::Field(field) => {
            let mut result = Vec::new();
            eval::each_value(context, field, |value| {
                result.push(value.into_owned());
                false
            });
            result
        }
        Operand::Function(Function::Count, inner) => {
            let selected = values(inner, context);
            if selected.is_empty() {
                Vec::new()
            } else {
                let mut scalars = Vec::new();
                for value in selected {
                    flatten(value, &mut scalars);
                }
                vec![FieldValue::Unsigned(scalars.len() as u64)]
            }
        }
        Operand::Function(func, inner) => values(inner, context)
            .into_iter()
            .filter_map(|value| match (func, value) {
                (Function::Len, FieldValue::Bytes(value)) => {
                    Some(FieldValue::Unsigned(value.len() as u64))
                }
                (Function::Len, FieldValue::Text(value)) => {
                    Some(FieldValue::Unsigned(value.len() as u64))
                }
                (Function::Len, FieldValue::Mac(_)) => Some(FieldValue::Unsigned(6)),
                (Function::Len, FieldValue::List(value)) => {
                    Some(FieldValue::Unsigned(value.len() as u64))
                }
                (Function::Lower, FieldValue::Text(value)) => {
                    Some(FieldValue::Text(value.to_ascii_lowercase()))
                }
                (Function::Upper, FieldValue::Text(value)) => {
                    Some(FieldValue::Text(value.to_ascii_uppercase()))
                }
                (Function::Lower, FieldValue::Bytes(value)) => {
                    Some(FieldValue::Bytes(Bytes::from(value.to_ascii_lowercase())))
                }
                (Function::Upper, FieldValue::Bytes(value)) => {
                    Some(FieldValue::Bytes(Bytes::from(value.to_ascii_uppercase())))
                }
                _ => None,
            })
            .collect(),
    }
}
fn byte_value(value: &FieldValue) -> Option<&[u8]> {
    match value {
        FieldValue::Bytes(v) => Some(v),
        FieldValue::Text(v) => Some(v.as_bytes()),
        _ => None,
    }
}
pub(super) fn test(predicate: &Predicate, context: &eval::Context<'_>) -> bool {
    let mut left = Vec::new();
    let mut right = Vec::new();
    for value in values(&predicate.left, context) {
        flatten(value, &mut left);
    }
    for value in values(&predicate.right, context) {
        flatten(value, &mut right);
    }
    if left.is_empty() || right.is_empty() {
        return false;
    }
    let pair = |left: &FieldValue, right: &FieldValue| match &predicate.operation {
        Operation::Compare(operator) => comparison::matches(
            left,
            *operator,
            &match &predicate.right {
                Operand::Literal(v) => v.clone(),
                _ => to_literal(right),
            },
        ),
        Operation::Regex(regex) => byte_value(left).is_some_and(|bytes| regex.is_match(bytes)),
        Operation::StartsWith => byte_value(left)
            .zip(byte_value(right))
            .is_some_and(|(left, right)| left.starts_with(right)),
        Operation::EndsWith => byte_value(left)
            .zip(byte_value(right))
            .is_some_and(|(left, right)| left.ends_with(right)),
    };
    if predicate.all {
        left.iter()
            .all(|left| right.iter().all(|right| pair(left, right)))
    } else {
        left.iter()
            .any(|left| right.iter().any(|right| pair(left, right)))
    }
}
fn to_literal(value: &FieldValue) -> Literal {
    match value {
        FieldValue::Bool(v) => Literal::Bool(*v),
        FieldValue::Unsigned(v) => Literal::Unsigned(*v),
        FieldValue::Signed(v) => Literal::Signed(*v),
        FieldValue::Text(v) => Literal::Text(v.clone()),
        FieldValue::Bytes(v) => Literal::Bytes(v.clone()),
        FieldValue::Mac(v) => Literal::Mac(*v),
        FieldValue::Ipv4(v) => Literal::Ipv4(*v),
        FieldValue::Ipv6(v) => Literal::Ipv6(*v),
        _ => Literal::Bool(false),
    }
}
