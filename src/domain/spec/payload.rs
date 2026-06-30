// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use super::error::{SpecError, SpecResult};

use crate::domain::request::PayloadRequest;

const DNS_MAX_NAME_LEN: usize = 253;
const DNS_MAX_LABEL_LEN: usize = 63;

#[derive(Debug, Clone, Default)]
pub(crate) struct PayloadSpec {
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
pub(crate) enum PayloadSource {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_spec_defaults_to_empty_source() {
        let spec = PayloadSpec::from_request(&PayloadRequest::default()).unwrap();

        assert!(matches!(spec.source, PayloadSource::Empty));
    }

    #[test]
    fn payload_spec_accepts_each_primary_source() {
        let cases = [
            (
                PayloadRequest {
                    data: Some("hello".to_string()),
                    ..Default::default()
                },
                "inline",
            ),
            (
                PayloadRequest {
                    data_hex: Some("6869".to_string()),
                    ..Default::default()
                },
                "hex",
            ),
            (
                PayloadRequest {
                    data_file: Some("/tmp/payload.bin".to_string()),
                    ..Default::default()
                },
                "file",
            ),
            (
                PayloadRequest {
                    random_payload_size: Some(32),
                    ..Default::default()
                },
                "random",
            ),
        ];

        for (request, expected) in cases {
            let spec = PayloadSpec::from_request(&request).unwrap();
            let actual = match spec.source {
                PayloadSource::Inline(_) => "inline",
                PayloadSource::Hex(_) => "hex",
                PayloadSource::File(_) => "file",
                PayloadSource::Random(_) => "random",
                _ => "other",
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn payload_spec_rejects_multiple_sources() {
        let err = PayloadSpec::from_request(&PayloadRequest {
            data: Some("hello".to_string()),
            data_hex: Some("6869".to_string()),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(err, SpecError::MultiplePayloadSources));
    }

    #[test]
    fn payload_spec_defaults_dns_record_type_to_a() {
        let spec = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some("example.test".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert!(matches!(
            spec.source,
            PayloadSource::Dns {
                query,
                record_type
            } if query == "example.test" && record_type == "A"
        ));
    }

    #[test]
    fn payload_spec_rejects_invalid_dns_hostname() {
        let err = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some("bad name".to_string()),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(
            err,
            SpecError::InvalidDnsHostname { field: "DNS query" }
        ));
    }

    #[test]
    fn payload_spec_accepts_http_with_defaults() {
        let spec = PayloadSpec::from_request(&PayloadRequest {
            http_method: Some("GET".to_string()),
            http_host: Some("example.test".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert!(matches!(
            spec.source,
            PayloadSource::Http {
                method,
                path,
                host: Some(host)
            } if method == "GET" && path == "/" && host == "example.test"
        ));
    }

    #[test]
    fn payload_spec_rejects_invalid_http_fields() {
        assert!(matches!(
            PayloadSpec::from_request(&PayloadRequest {
                http_method: Some("bad method".to_string()),
                ..Default::default()
            })
            .unwrap_err(),
            SpecError::InvalidHttpMethod
        ));
        assert!(matches!(
            PayloadSpec::from_request(&PayloadRequest {
                http_method: Some("GET".to_string()),
                http_path: Some("relative".to_string()),
                ..Default::default()
            })
            .unwrap_err(),
            SpecError::InvalidHttpPath
        ));
        assert!(matches!(
            PayloadSpec::from_request(&PayloadRequest {
                http_method: Some("GET".to_string()),
                http_host: Some("bad host".to_string()),
                ..Default::default()
            })
            .unwrap_err(),
            SpecError::InvalidHttpHost
        ));
    }

    #[test]
    fn payload_spec_accepts_tls_sni() {
        let spec = PayloadSpec::from_request(&PayloadRequest {
            tls_client_hello: Some("example.test".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert!(matches!(
            spec.source,
            PayloadSource::TlsClientHello { server_name } if server_name == "example.test"
        ));
    }

    #[test]
    fn payload_spec_rejects_root_tls_sni() {
        let err = PayloadSpec::from_request(&PayloadRequest {
            tls_client_hello: Some(".".to_string()),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(
            err,
            SpecError::InvalidDnsHostname { field: "TLS SNI" }
        ));
    }
}
