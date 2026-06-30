// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::path::PathBuf;

#[cfg(any(not(feature = "pcap"), not(feature = "metrics")))]
use super::error::SpecError;
use super::error::SpecResult;

use crate::domain::request::{LogLevel, LoggingRequest};

#[derive(Debug, Clone, Default)]
pub(crate) struct LoggingSpec {
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
