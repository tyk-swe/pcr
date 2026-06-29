// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use super::error::{SpecError, SpecResult};

use crate::domain::request::PayloadRequest;

const DNS_MAX_NAME_LEN: usize = 253;
const DNS_MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, Default)]
pub struct PayloadSpec {
    pub source: PayloadSource,
}

impl PayloadSpec {
    pub(crate) fn from_request(request: &PayloadRequest) -> SpecResult<Self> {
        let mut selected = None;

        if let Some(data) = request.data.as_ref() {
            selected = Some(PayloadSource::Inline(data.clone()));
        }
        if let Some(hex) = request.data_hex.as_ref() {
            ensure_payload_slot(&mut selected, PayloadSource::Hex(hex.clone()))?;
        }
        if let Some(file) = request.data_file.as_ref() {
            ensure_payload_slot(&mut selected, PayloadSource::File(PathBuf::from(file)))?;
        }
        if let Some(size) = request.random_payload_size {
            ensure_payload_slot(&mut selected, PayloadSource::Random(size))?;
        }
        if let Some(query) = request.dns_query.as_ref() {
            validate_dns_query_name(query)?;
            ensure_payload_slot(
                &mut selected,
                PayloadSource::Dns {
                    query: query.clone(),
                    record_type: request.dns_type.clone().unwrap_or_else(|| "A".to_string()),
                },
            )?;
        }
        if let Some(method) = request.http_method.as_ref() {
            validate_http_method(method)?;
            let path = request.http_path.clone().unwrap_or_else(|| "/".to_string());
            validate_http_path(&path)?;
            if let Some(host) = request.http_host.as_ref() {
                validate_http_host(host)?;
            }
            ensure_payload_slot(
                &mut selected,
                PayloadSource::Http {
                    method: method.clone(),
                    path,
                    host: request.http_host.clone(),
                },
            )?;
        }
        if let Some(sni) = request.tls_client_hello.as_ref() {
            validate_dns_hostname("TLS SNI", sni, false)?;
            ensure_payload_slot(
                &mut selected,
                PayloadSource::TlsClientHello {
                    server_name: sni.clone(),
                },
            )?;
        }

        Ok(Self {
            source: selected.unwrap_or(PayloadSource::Empty),
        })
    }
}

fn ensure_payload_slot(slot: &mut Option<PayloadSource>, value: PayloadSource) -> SpecResult<()> {
    if slot.is_some() {
        return Err(SpecError::MultiplePayloadSources);
    }
    *slot = Some(value);
    Ok(())
}

fn validate_http_method(method: &str) -> SpecResult<()> {
    if method.is_empty() || !method.bytes().all(is_http_token_byte) {
        return Err(SpecError::InvalidHttpMethod);
    }
    Ok(())
}

fn is_http_token_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'#'
            | b'$'
            | b'%'
            | b'&'
            | b'\''
            | b'*'
            | b'+'
            | b'-'
            | b'.'
            | b'^'
            | b'_'
            | b'`'
            | b'|'
            | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
    )
}

fn validate_http_path(path: &str) -> SpecResult<()> {
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return Err(SpecError::InvalidHttpPath);
    }
    Ok(())
}

fn validate_http_host(host: &str) -> SpecResult<()> {
    if host.is_empty() || host.chars().any(|ch| ch.is_control() || ch.is_whitespace()) {
        return Err(SpecError::InvalidHttpHost);
    }
    Ok(())
}

fn validate_dns_query_name(value: &str) -> SpecResult<()> {
    validate_dns_hostname("DNS query", value, true)
}

fn validate_dns_hostname(field: &'static str, value: &str, allow_root: bool) -> SpecResult<()> {
    if value.is_empty()
        || !value.is_ascii()
        || value
            .chars()
            .any(|ch| ch.is_control() || ch.is_ascii_whitespace())
    {
        return Err(SpecError::InvalidDnsHostname { field });
    }

    let name = value.strip_suffix('.').unwrap_or(value);
    if name.is_empty() {
        if allow_root && value == "." {
            return Ok(());
        }
        return Err(SpecError::InvalidDnsHostname { field });
    }

    if name.len() > DNS_MAX_NAME_LEN {
        return Err(SpecError::InvalidDnsHostname { field });
    }

    if name
        .split('.')
        .any(|label| label.is_empty() || label.len() > DNS_MAX_LABEL_LEN)
    {
        return Err(SpecError::InvalidDnsHostname { field });
    }

    Ok(())
}

#[derive(Debug, Clone, Default)]
pub enum PayloadSource {
    #[default]
    Empty,
    Inline(String),
    Hex(String),
    File(PathBuf),
    Random(usize),
    Dns {
        query: String,
        record_type: String,
    },
    Http {
        method: String,
        path: String,
        host: Option<String>,
    },
    TlsClientHello {
        server_name: String,
    },
    Bytes(Vec<u8>),
}
