use std::net::IpAddr;
use std::time::Duration;

use serde::Serialize;

use crate::packet::internal::Diagnostic;
use crate::workflow::scan::Result as ScanResult;

use super::contract::OutputContractError;
use super::envelope::OperationStats;
use super::frame::{FrameOutput, OutputTimestamp};

/// Output-v1 scan classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanClassification {
    Open,
    Closed,
    Filtered,
    Unreachable,
    Unknown,
    Timeout,
}

impl From<crate::workflow::scan::Classification> for ScanClassification {
    fn from(value: crate::workflow::scan::Classification) -> Self {
        match value {
            crate::workflow::scan::Classification::Open => Self::Open,
            crate::workflow::scan::Classification::Closed => Self::Closed,
            crate::workflow::scan::Classification::Filtered => Self::Filtered,
            crate::workflow::scan::Classification::Unreachable => Self::Unreachable,
            crate::workflow::scan::Classification::Unknown => Self::Unknown,
            crate::workflow::scan::Classification::Timeout => Self::Timeout,
        }
    }
}

/// Output-v1 scan-probe status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanProbeStatus {
    Response,
    Timeout,
}

impl From<crate::workflow::scan::ProbeStatus> for ScanProbeStatus {
    fn from(value: crate::workflow::scan::ProbeStatus) -> Self {
        match value {
            crate::workflow::scan::ProbeStatus::Response => Self::Response,
            crate::workflow::scan::ProbeStatus::Timeout => Self::Timeout,
        }
    }
}

/// Evidence common to scan and other active-probe tools.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProbeEvidenceOutput {
    pub protocol: String,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub attempt: u32,
    pub status: ScanProbeStatus,
    pub classification: ScanClassification,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder: Option<IpAddr>,
    pub sent_at: OutputTimestamp,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub received_at: Option<OutputTimestamp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frame: Option<FrameOutput>,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanPortOutput {
    pub port: u16,
    pub transport: String,
    pub classification: ScanClassification,
    pub evidence: Vec<ProbeEvidenceOutput>,
}

impl ScanPortOutput {
    pub fn try_from_endpoint_ref(
        endpoint: &crate::workflow::scan::Endpoint,
    ) -> Result<Self, OutputContractError> {
        let evidence = endpoint
            .evidence
            .iter()
            .map(|evidence| {
                let protocol = match (endpoint.transport, endpoint.address) {
                    (crate::workflow::scan::Transport::Icmp, IpAddr::V4(_)) => "icmpv4",
                    (crate::workflow::scan::Transport::Icmp, IpAddr::V6(_)) => "icmpv6",
                    _ => endpoint.transport.as_str(),
                };
                Ok(ProbeEvidenceOutput {
                    protocol: protocol.to_owned(),
                    destination: endpoint.address,
                    destination_port: endpoint.port,
                    attempt: evidence.attempt,
                    status: evidence.status.into(),
                    classification: evidence.classification.into(),
                    responder: evidence.responder,
                    sent_at: evidence.sent_at.try_into()?,
                    received_at: evidence
                        .received_at
                        .map(OutputTimestamp::try_from)
                        .transpose()?,
                    latency: evidence.latency,
                    frame: evidence
                        .response
                        .as_ref()
                        .map(FrameOutput::try_from_frame_ref)
                        .transpose()?,
                    reason: evidence.reason.clone(),
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        Ok(Self {
            // Port zero is the versioned sentinel for a portless ICMP
            // endpoint; destination_port remains absent in evidence.
            port: endpoint.port.unwrap_or(0),
            transport: endpoint.transport.to_string(),
            classification: endpoint.classification.into(),
            evidence,
        })
    }
}

/// Aggregate or streamed result of `scan`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanCommandResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub ports: Vec<ScanPortOutput>,
    pub undecoded: Vec<FrameOutput>,
}

impl ScanCommandResult {
    pub fn try_from_scan(
        result: ScanResult,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let ScanResult {
            target,
            resolved_addresses,
            endpoints,
            undecoded,
            diagnostics,
            stats,
        } = result;
        let port_outputs = endpoints
            .iter()
            .map(ScanPortOutput::try_from_endpoint_ref)
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let undecoded_frames = undecoded
            .into_iter()
            .map(FrameOutput::try_from_frame)
            .collect::<Result<Vec<_>, _>>()?;
        let operation_stats = stats.into();
        Ok((
            Self {
                target,
                resolved_addresses,
                ports: port_outputs,
                undecoded: undecoded_frames,
            },
            diagnostics,
            operation_stats,
        ))
    }
}

/// One classified port record produced by streaming `scan` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ScanPortCommandResult {
    pub target: String,
    pub resolved_address: IpAddr,
    pub port: ScanPortOutput,
}

/// One independently useful event in structured scan streaming output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ScanStreamCommandResult {
    Port {
        target: String,
        resolved_address: IpAddr,
        port: ScanPortOutput,
    },
    Undecoded {
        frame: FrameOutput,
    },
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
    },
}
