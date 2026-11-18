// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::model::Header;
use crate::analysis::http_headers;

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

pub(crate) fn recover(role: FieldRole, fields: &[Header]) -> Meta {
    http_headers::recover(role, fields.iter().map(|field| (&field.name, &field.value)))
}

#[cfg(test)]
mod tests;
