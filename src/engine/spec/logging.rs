// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

#[cfg(any(not(feature = "pcap"), not(feature = "metrics")))]
use super::error::SpecError;
use super::error::SpecResult;

use crate::engine::request::{LogLevel, LoggingRequest};

#[derive(Debug, Clone, Default)]
pub struct LoggingSpec {
    pub log_file: Option<PathBuf>,
    pub pcap_write: Option<PathBuf>,
    pub metrics_json: Option<PathBuf>,
    pub log_level: Option<LogLevel>,
    pub structured: bool,
    pub prometheus_bind: Option<String>,
    pub allow_public_metrics: bool,
}

impl LoggingSpec {
    pub(crate) fn from_request(request: &LoggingRequest) -> SpecResult<Self> {
        #[cfg(not(feature = "pcap"))]
        if request.pcap_write.is_some() {
            return Err(SpecError::PcapWriteRequiresFeature);
        }

        #[cfg(not(feature = "metrics"))]
        if request.metrics_json.is_some()
            || request.prometheus_bind.is_some()
            || request.allow_public_metrics.unwrap_or(false)
        {
            return Err(SpecError::MetricsRequiresFeature);
        }

        Ok(Self {
            log_file: request.log_file.as_ref().map(PathBuf::from),
            pcap_write: request.pcap_write.as_ref().map(PathBuf::from),
            metrics_json: request.metrics_json.as_ref().map(PathBuf::from),
            log_level: request.log_level,
            structured: request.structured.unwrap_or(false),
            prometheus_bind: request.prometheus_bind.clone(),
            allow_public_metrics: request.allow_public_metrics.unwrap_or(false),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "pcap")]
    #[test]
    fn from_options_pcap_write_enabled() {
        let options = LoggingRequest {
            pcap_write: Some("capture.pcap".to_string()),
            ..Default::default()
        };
        let spec = LoggingSpec::from_request(&options).unwrap();
        assert_eq!(spec.pcap_write, Some(PathBuf::from("capture.pcap")));
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn from_options_pcap_write_disabled_error() {
        let options = LoggingRequest {
            pcap_write: Some("capture.pcap".to_string()),
            ..Default::default()
        };
        let result = LoggingSpec::from_request(&options);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            SpecError::PcapWriteRequiresFeature
        ));
    }

    #[cfg(feature = "metrics")]
    #[test]
    fn from_options_metrics_enabled() {
        let options = LoggingRequest {
            metrics_json: Some("metrics.json".to_string()),
            prometheus_bind: Some("127.0.0.1:9898".to_string()),
            allow_public_metrics: Some(true),
            ..Default::default()
        };
        let spec = LoggingSpec::from_request(&options).unwrap();
        assert_eq!(spec.metrics_json, Some(PathBuf::from("metrics.json")));
        assert_eq!(spec.prometheus_bind, Some("127.0.0.1:9898".to_string()));
        assert!(spec.allow_public_metrics);
    }

    #[cfg(not(feature = "metrics"))]
    #[test]
    fn from_options_metrics_json_disabled_error() {
        let options = LoggingRequest {
            metrics_json: Some("metrics.json".to_string()),
            ..Default::default()
        };
        let result = LoggingSpec::from_request(&options);
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MetricsRequiresFeature
        ));
    }

    #[cfg(not(feature = "metrics"))]
    #[test]
    fn from_options_prometheus_disabled_error() {
        let options = LoggingRequest {
            prometheus_bind: Some("127.0.0.1:9898".to_string()),
            ..Default::default()
        };
        let result = LoggingSpec::from_request(&options);
        assert!(matches!(
            result.unwrap_err(),
            SpecError::MetricsRequiresFeature
        ));
    }

    #[cfg(not(feature = "metrics"))]
    #[test]
    fn from_options_allow_public_metrics_false_is_not_metrics_use() {
        let options = LoggingRequest {
            allow_public_metrics: Some(false),
            ..Default::default()
        };
        let spec = LoggingSpec::from_request(&options).unwrap();
        assert!(!spec.allow_public_metrics);
    }
}
