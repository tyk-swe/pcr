// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::{Ipv4Addr, Ipv6Addr};
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
    if host.is_empty()
        || host.chars().any(|ch| ch.is_control() || ch.is_whitespace())
        || host.contains(['/', '?', '#'])
    {
        return Err(SpecError::InvalidHttpHost);
    }

    if let Some(rest) = host.strip_prefix('[') {
        return validate_bracketed_ipv6_authority(rest);
    }

    if host.contains(['[', ']']) {
        return Err(SpecError::InvalidHttpHost);
    }

    let colon_count = host.bytes().filter(|byte| *byte == b':').count();
    if colon_count > 1 {
        return Err(SpecError::InvalidHttpHost);
    }

    let host_part = if colon_count == 1 {
        let (host_part, port) = host.rsplit_once(':').ok_or(SpecError::InvalidHttpHost)?;
        validate_http_authority_port(port)?;
        host_part
    } else {
        host
    };

    validate_http_authority_host(host_part)
}

fn validate_bracketed_ipv6_authority(rest: &str) -> SpecResult<()> {
    let (addr, suffix) = rest.split_once(']').ok_or(SpecError::InvalidHttpHost)?;
    if addr.parse::<Ipv6Addr>().is_err() {
        return Err(SpecError::InvalidHttpHost);
    }

    if suffix.is_empty() {
        return Ok(());
    }

    let port = suffix.strip_prefix(':').ok_or(SpecError::InvalidHttpHost)?;
    validate_http_authority_port(port)
}

fn validate_http_authority_host(host: &str) -> SpecResult<()> {
    if host.is_empty() {
        return Err(SpecError::InvalidHttpHost);
    }

    if host.parse::<Ipv4Addr>().is_ok() || is_valid_reg_name(host) {
        Ok(())
    } else {
        Err(SpecError::InvalidHttpHost)
    }
}

fn validate_http_authority_port(port: &str) -> SpecResult<()> {
    if port.is_empty()
        || !port.bytes().all(|byte| byte.is_ascii_digit())
        || port.parse::<u16>().is_err()
    {
        return Err(SpecError::InvalidHttpHost);
    }
    Ok(())
}

fn is_valid_reg_name(host: &str) -> bool {
    if host.is_empty() || !host.is_ascii() {
        return false;
    }

    let bytes = host.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                let Some(encoded) = bytes.get(index + 1..index + 3) else {
                    return false;
                };
                if !encoded.iter().all(u8::is_ascii_hexdigit) {
                    return false;
                }
                index += 3;
            }
            byte if is_reg_name_unescaped_byte(byte) => {
                index += 1;
            }
            _ => return false,
        }
    }

    true
}

fn is_reg_name_unescaped_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'.'
            | b'_'
            | b'~'
            | b'!'
            | b'$'
            | b'&'
            | b'\''
            | b'('
            | b')'
            | b'*'
            | b'+'
            | b','
            | b';'
            | b'='
    )
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
    #[cfg(any(test, feature = "fuzz"))]
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
    fn payload_spec_accepts_dns_root_and_maximum_hostname_length() {
        let root = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some(".".to_string()),
            dns_type: Some("NS".to_string()),
            ..Default::default()
        })
        .unwrap();
        let max_name = [
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61),
        ]
        .join(".");
        let max = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some(max_name.clone()),
            ..Default::default()
        })
        .unwrap();

        assert!(matches!(
            root.source,
            PayloadSource::Dns {
                query,
                record_type
            } if query == "." && record_type == "NS"
        ));
        assert!(matches!(
            max.source,
            PayloadSource::Dns { query, .. } if query == max_name
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
    fn payload_spec_rejects_dns_label_and_name_length_overflow() {
        let long_label = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some(format!("{}.test", "a".repeat(64))),
            ..Default::default()
        })
        .unwrap_err();
        let long_name = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some(
                [
                    "a".repeat(63),
                    "b".repeat(63),
                    "c".repeat(63),
                    "d".repeat(62),
                ]
                .join("."),
            ),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(
            long_label,
            SpecError::InvalidDnsHostname { field: "DNS query" }
        ));
        assert!(matches!(
            long_name,
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
    fn payload_spec_accepts_valid_http_host_authorities() {
        for host in [
            "example.test",
            "example.test:8080",
            "localhost",
            "127.0.0.1",
            "127.0.0.1:80",
            "[2001:db8::1]",
            "[2001:db8::1]:443",
            "xn--bcher-kva.example",
            "service_name.example",
            "name%2Dencoded.example",
        ] {
            let spec = PayloadSpec::from_request(&PayloadRequest {
                http_method: Some("GET".to_string()),
                http_host: Some(host.to_string()),
                ..Default::default()
            })
            .unwrap();

            assert!(matches!(
                spec.source,
                PayloadSource::Http { host: Some(ref actual), .. } if actual == host
            ));
        }
    }

    #[test]
    fn payload_spec_rejects_invalid_http_host_authorities() {
        for host in [
            "",
            "bad host",
            "bad\thost",
            "example.test/path",
            "example.test?x=1",
            "example.test#frag",
            "example.test:",
            "example.test:http",
            "example.test:65536",
            ":443",
            "2001:db8::1",
            "[2001:db8::1",
            "[2001:db8::1]extra",
            "[2001:db8::1]:",
            "[2001:db8::1]:notaport",
            "[2001:db8::1]:65536",
            "[not::ip]",
            "[127.0.0.1]",
            "name%zz.example",
            "user@example.test",
        ] {
            let err = PayloadSpec::from_request(&PayloadRequest {
                http_method: Some("GET".to_string()),
                http_host: Some(host.to_string()),
                ..Default::default()
            })
            .unwrap_err();

            assert!(matches!(err, SpecError::InvalidHttpHost), "host={host}");
        }
    }

    #[test]
    fn payload_spec_accepts_http_token_punctuation_and_absolute_path() {
        let spec = PayloadSpec::from_request(&PayloadRequest {
            http_method: Some("PATCH+JSON".to_string()),
            http_path: Some("/nested/resource?x=1".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert!(matches!(
            spec.source,
            PayloadSource::Http { method, path, host: None }
                if method == "PATCH+JSON" && path == "/nested/resource?x=1"
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
