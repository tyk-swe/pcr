// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::model::Header;
use crate::{analysis::http_headers, protocol::application::http::token};
use bytes::Bytes;

pub(crate) use http_headers::{FieldRole, Meta};
pub(super) use http_headers::{
    authorities_equal, valid_authority, valid_http_authority, valid_uri_path,
};

pub(crate) fn validate(role: FieldRole, fields: &[Header]) -> Result<Meta, &'static str> {
    let meta =
        http_headers::validate(role, fields.iter().map(|field| (&field.name, &field.value)))?;
    if meta.status == Some(101) {
        return Err("101 is not a valid HTTP/2 response status");
    }
    Ok(meta)
}

/// Recover only an unambiguous, syntactically valid response status after
/// other header semantics failed, so informational/final sequencing survives.
pub(crate) fn response_status(fields: &[Header]) -> Option<u16> {
    http_headers::response_status(fields.iter().map(|field| (&field.name, &field.value)))
}

/// Preserve method-dependent response semantics after unrelated field errors.
pub(crate) fn request_method(fields: &[Header]) -> Option<Bytes> {
    let mut methods = fields
        .iter()
        .filter(|field| field.name.as_ref() == b":method");
    let value = &methods.next()?.value;
    if methods.next().is_some() || value.is_empty() || !value.iter().all(|b| token(*b)) {
        return None;
    }
    Some(value.clone())
}

#[cfg(test)]
mod tests;
