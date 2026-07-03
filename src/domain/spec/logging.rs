// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

use super::error::SpecResult;

use crate::domain::request::LoggingRequest;

#[cfg(feature = "pcap")]
mod pcap_write {
    use super::*;

    pub(super) fn validate(_request: &LoggingRequest) -> SpecResult<()> {
        Ok(())
    }
}

#[cfg(not(feature = "pcap"))]
mod pcap_write {
    use super::super::error::SpecError;
    use super::*;

    pub(super) fn validate(request: &LoggingRequest) -> SpecResult<()> {
        if request.pcap_write.is_some() {
            return Err(SpecError::PcapWriteRequiresFeature);
        }
        Ok(())
    }
}

#[cfg(feature = "metrics")]
mod metrics {
    use super::*;

    pub(super) fn validate(_request: &LoggingRequest) -> SpecResult<()> {
        Ok(())
    }
}

#[cfg(not(feature = "metrics"))]
mod metrics {
    use super::super::error::SpecError;
    use super::*;

    pub(super) fn validate(request: &LoggingRequest) -> SpecResult<()> {
        if request.metrics_json.is_some()
            || request.prometheus_bind.is_some()
            || request.allow_public_metrics.unwrap_or(false)
        {
            return Err(SpecError::MetricsRequiresFeature);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct LoggingSpec {
    pub log_file: Option<PathBuf>,
    pub pcap_write: Option<PathBuf>,
    pub metrics_json: Option<PathBuf>,
}

impl LoggingSpec {
    pub(crate) fn from_request(request: &LoggingRequest) -> SpecResult<Self> {
        pcap_write::validate(request)?;
        metrics::validate(request)?;

        Ok(Self {
            log_file: request.log_file.as_ref().map(PathBuf::from),
            pcap_write: request.pcap_write.as_ref().map(PathBuf::from),
            metrics_json: request.metrics_json.as_ref().map(PathBuf::from),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(any(not(feature = "pcap"), not(feature = "metrics")))]
    use super::super::error::SpecError;

    #[test]
    fn logging_spec_maps_supported_fields() {
        let spec = LoggingSpec::from_request(&LoggingRequest {
            log_file: Some("packets.log".to_string()),
            ..Default::default()
        })
        .unwrap();

        assert_eq!(
            spec.log_file
                .as_ref()
                .map(|path| path.display().to_string()),
            Some("packets.log".to_string())
        );
    }

    #[cfg(not(feature = "pcap"))]
    #[test]
    fn logging_spec_without_pcap_rejects_pcap_write() {
        let err = LoggingSpec::from_request(&LoggingRequest {
            pcap_write: Some("out.pcap".to_string()),
            ..Default::default()
        })
        .unwrap_err();

        assert!(matches!(err, SpecError::PcapWriteRequiresFeature));
    }

    #[cfg(not(feature = "metrics"))]
    #[test]
    fn logging_spec_without_metrics_rejects_metrics_outputs() {
        for request in [
            LoggingRequest {
                metrics_json: Some("metrics.json".to_string()),
                ..Default::default()
            },
            LoggingRequest {
                prometheus_bind: Some("127.0.0.1:9090".to_string()),
                ..Default::default()
            },
            LoggingRequest {
                allow_public_metrics: Some(true),
                ..Default::default()
            },
        ] {
            let err = LoggingSpec::from_request(&request).unwrap_err();

            assert!(matches!(err, SpecError::MetricsRequiresFeature));
        }
    }
}
