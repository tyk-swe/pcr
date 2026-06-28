use std::path::PathBuf;

use super::error::{SpecError, SpecResult};

use crate::engine::request::PayloadRequest;

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
            ensure_payload_slot(
                &mut selected,
                PayloadSource::Dns {
                    query: query.clone(),
                    record_type: request.dns_type.clone().unwrap_or_else(|| "A".to_string()),
                },
            )?;
        }
        if let Some(method) = request.http_method.as_ref() {
            ensure_payload_slot(
                &mut selected,
                PayloadSource::Http {
                    method: method.clone(),
                    path: request.http_path.clone().unwrap_or_else(|| "/".to_string()),
                    host: request.http_host.clone(),
                },
            )?;
        }
        if let Some(sni) = request.tls_client_hello.as_ref() {
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
}
