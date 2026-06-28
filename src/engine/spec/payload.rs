// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use super::error::{SpecError, SpecResult};

use crate::engine::request::PayloadRequest;

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::request::PayloadRequest;

    #[test]
    fn payload_spec_rejects_multiple_sources_inline_and_hex() {
        let options = PayloadRequest {
            data: Some("test".to_string()),
            data_hex: Some("deadbeef".to_string()),
            ..Default::default()
        };
        let result = PayloadSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MultiplePayloadSources
        ));
    }

    #[test]
    fn payload_spec_rejects_multiple_sources_inline_and_file() {
        let options = PayloadRequest {
            data: Some("test".to_string()),
            data_file: Some("/path/to/file".to_string()),
            ..Default::default()
        };
        let result = PayloadSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MultiplePayloadSources
        ));
    }

    #[test]
    fn payload_spec_rejects_multiple_sources_hex_and_random() {
        let options = PayloadRequest {
            data_hex: Some("deadbeef".to_string()),
            random_payload_size: Some(512),
            ..Default::default()
        };
        let result = PayloadSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MultiplePayloadSources
        ));
    }

    #[test]
    fn payload_spec_rejects_multiple_sources_file_and_random() {
        let options = PayloadRequest {
            data_file: Some("/path/to/file".to_string()),
            random_payload_size: Some(256),
            ..Default::default()
        };
        let result = PayloadSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MultiplePayloadSources
        ));
    }

    #[test]
    fn payload_spec_rejects_all_sources() {
        let options = PayloadRequest {
            data: Some("test".to_string()),
            data_hex: Some("deadbeef".to_string()),
            data_file: Some("/path/to/file".to_string()),
            random_payload_size: Some(128),
            ..Default::default()
        };
        let result = PayloadSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MultiplePayloadSources
        ));
    }

    #[test]
    fn payload_spec_rejects_multiple_sources_dns_and_http() {
        let options = PayloadRequest {
            dns_query: Some("example.com".to_string()),
            http_method: Some("GET".to_string()),
            ..Default::default()
        };
        let result = PayloadSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MultiplePayloadSources
        ));
    }

    #[test]
    fn payload_spec_rejects_multiple_sources_dns_and_data() {
        let options = PayloadRequest {
            dns_query: Some("example.com".to_string()),
            data: Some("inline".to_string()),
            ..Default::default()
        };
        let result = PayloadSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MultiplePayloadSources
        ));
    }

    #[test]
    fn payload_spec_rejects_multiple_sources_http_and_tls() {
        let options = PayloadRequest {
            http_method: Some("GET".to_string()),
            tls_client_hello: Some("example.com".to_string()),
            ..Default::default()
        };
        let result = PayloadSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MultiplePayloadSources
        ));
    }

    fn max_dns_name() -> String {
        format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        )
    }

    #[test]
    fn payload_spec_accepts_valid_structured_helpers() {
        let dns = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some("example.com".to_string()),
            dns_type: Some("AAAA".to_string()),
            ..Default::default()
        })
        .expect("dns payload spec");
        assert!(matches!(
            dns.source,
            PayloadSource::Dns {
                ref query,
                ref record_type,
            } if query == "example.com" && record_type == "AAAA"
        ));

        let root_dns = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some(".".to_string()),
            ..Default::default()
        })
        .expect("root dns payload spec");
        assert!(matches!(
            root_dns.source,
            PayloadSource::Dns {
                ref query,
                ref record_type,
            } if query == "." && record_type == "A"
        ));

        let http = PayloadSpec::from_request(&PayloadRequest {
            http_method: Some("POST".to_string()),
            http_path: Some("/api".to_string()),
            http_host: Some("example.com".to_string()),
            ..Default::default()
        })
        .expect("http payload spec");
        assert!(matches!(
            http.source,
            PayloadSource::Http {
                ref method,
                ref path,
                ref host,
            } if method == "POST" && path == "/api" && host.as_deref() == Some("example.com")
        ));

        let tls = PayloadSpec::from_request(&PayloadRequest {
            tls_client_hello: Some(max_dns_name()),
            ..Default::default()
        })
        .expect("tls payload spec");
        assert!(matches!(
            tls.source,
            PayloadSource::TlsClientHello { ref server_name } if server_name.len() == DNS_MAX_NAME_LEN
        ));
    }

    #[test]
    fn payload_spec_rejects_http_invalid_shapes() {
        let empty_method = PayloadSpec::from_request(&PayloadRequest {
            http_method: Some(String::new()),
            ..Default::default()
        });
        assert!(matches!(empty_method, Err(SpecError::InvalidHttpMethod)));

        let path_without_slash = PayloadSpec::from_request(&PayloadRequest {
            http_method: Some("GET".to_string()),
            http_path: Some("index.html".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            path_without_slash,
            Err(SpecError::InvalidHttpPath)
        ));

        let host_with_space = PayloadSpec::from_request(&PayloadRequest {
            http_method: Some("GET".to_string()),
            http_host: Some("bad host".to_string()),
            ..Default::default()
        });
        assert!(matches!(host_with_space, Err(SpecError::InvalidHttpHost)));
    }

    #[test]
    fn payload_spec_rejects_control_characters_in_structured_helpers() {
        let http_method = PayloadSpec::from_request(&PayloadRequest {
            http_method: Some("GE\nT".to_string()),
            ..Default::default()
        });
        assert!(matches!(http_method, Err(SpecError::InvalidHttpMethod)));

        let http_path = PayloadSpec::from_request(&PayloadRequest {
            http_method: Some("GET".to_string()),
            http_path: Some("/bad\rpath".to_string()),
            ..Default::default()
        });
        assert!(matches!(http_path, Err(SpecError::InvalidHttpPath)));

        let http_host = PayloadSpec::from_request(&PayloadRequest {
            http_method: Some("GET".to_string()),
            http_host: Some("example\n.com".to_string()),
            ..Default::default()
        });
        assert!(matches!(http_host, Err(SpecError::InvalidHttpHost)));

        let dns = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some("example\n.com".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            dns,
            Err(SpecError::InvalidDnsHostname { field: "DNS query" })
        ));

        let tls = PayloadSpec::from_request(&PayloadRequest {
            tls_client_hello: Some("example\t.com".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            tls,
            Err(SpecError::InvalidDnsHostname { field: "TLS SNI" })
        ));
    }

    #[test]
    fn payload_spec_rejects_invalid_and_oversized_dns_names() {
        let empty_dns = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some(String::new()),
            ..Default::default()
        });
        assert!(matches!(
            empty_dns,
            Err(SpecError::InvalidDnsHostname { field: "DNS query" })
        ));

        let non_ascii_tls = PayloadSpec::from_request(&PayloadRequest {
            tls_client_hello: Some("exämple.com".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            non_ascii_tls,
            Err(SpecError::InvalidDnsHostname { field: "TLS SNI" })
        ));

        let root_tls = PayloadSpec::from_request(&PayloadRequest {
            tls_client_hello: Some(".".to_string()),
            ..Default::default()
        });
        assert!(matches!(
            root_tls,
            Err(SpecError::InvalidDnsHostname { field: "TLS SNI" })
        ));

        let long_label = PayloadSpec::from_request(&PayloadRequest {
            dns_query: Some(format!("{}.com", "a".repeat(64))),
            ..Default::default()
        });
        assert!(matches!(
            long_label,
            Err(SpecError::InvalidDnsHostname { field: "DNS query" })
        ));

        let oversized_name = PayloadSpec::from_request(&PayloadRequest {
            tls_client_hello: Some(format!("{}.e", max_dns_name())),
            ..Default::default()
        });
        assert!(matches!(
            oversized_name,
            Err(SpecError::InvalidDnsHostname { field: "TLS SNI" })
        ));
    }
}
