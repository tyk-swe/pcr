// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::network::sender::error::{ExecutorError, Result};

use super::super::super::super::types::NetworkTransmissionPlan;

pub(crate) struct CaptureWriter;

impl CaptureWriter {
    pub(crate) fn for_plan(plan: &NetworkTransmissionPlan) -> Result<Self> {
        if let Some(path) = plan.logging.pcap_write.as_ref() {
            return Err(ExecutorError::PcapFeatureRequired { path: path.clone() }.into());
        }

        Ok(Self)
    }

    pub(crate) fn record(&mut self, _frame: &[u8]) -> Result<()> {
        Ok(())
    }

    pub(crate) fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
