/// Output-v1 traceroute-probe status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceProbeStatus {
    Response,
    Timeout,
}

impl From<crate::workflow::traceroute::ProbeStatus> for TraceProbeStatus {
    fn from(value: crate::workflow::traceroute::ProbeStatus) -> Self {
        match value {
            crate::workflow::traceroute::ProbeStatus::Response => Self::Response,
            crate::workflow::traceroute::ProbeStatus::Timeout => Self::Timeout,
        }
    }
}

/// Output-v1 traceroute response classification.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceResponseKind {
    Intermediate,
    DestinationReached,
    Unreachable,
}

impl From<crate::workflow::traceroute::ResponseKind> for TraceResponseKind {
    fn from(value: crate::workflow::traceroute::ResponseKind) -> Self {
        match value {
            crate::workflow::traceroute::ResponseKind::Intermediate => Self::Intermediate,
            crate::workflow::traceroute::ResponseKind::DestinationReached => {
                Self::DestinationReached
            }
            crate::workflow::traceroute::ResponseKind::Unreachable => Self::Unreachable,
        }
    }
}

/// Output-v1 traceroute completion reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TraceCompletionReason {
    DestinationReached,
    Unreachable,
    MaximumHops,
    Timeout,
}

impl From<crate::workflow::traceroute::Completion> for TraceCompletionReason {
    fn from(value: crate::workflow::traceroute::Completion) -> Self {
        match value {
            crate::workflow::traceroute::Completion::DestinationReached => Self::DestinationReached,
            crate::workflow::traceroute::Completion::Unreachable => Self::Unreachable,
            crate::workflow::traceroute::Completion::MaximumHops => Self::MaximumHops,
            crate::workflow::traceroute::Completion::Timeout => Self::Timeout,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceProbeOutput {
    pub sequence: u64,
    pub hop_limit: u8,
    pub attempt: u32,
    pub strategy: String,
    pub destination: IpAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub status: TraceProbeStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_kind: Option<TraceResponseKind>,
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
pub struct TraceHopOutput {
    pub hop_limit: u8,
    pub probes: Vec<TraceProbeOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TraceUndecodedOutput {
    pub hop_limit: u8,
    pub frame: FrameOutput,
}

/// Aggregate or streamed result of `traceroute`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TracerouteCommandResult {
    pub target: String,
    pub resolved_addresses: Vec<IpAddr>,
    pub destination: IpAddr,
    pub strategy: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    pub hops: Vec<TraceHopOutput>,
    pub undecoded: Vec<TraceUndecodedOutput>,
    pub completion: TraceCompletionReason,
}

impl TracerouteCommandResult {
    pub fn try_from_traceroute(
        result: TracerouteResult,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let TracerouteResult {
            target,
            resolved_addresses,
            destination,
            strategy,
            destination_port,
            hops,
            undecoded,
            completion,
            diagnostics,
            stats,
        } = result;
        let hop_outputs = hops
            .into_iter()
            .map(|hop| {
                let probe_outputs = hop
                    .probes
                    .into_iter()
                    .map(|probe| {
                        Ok(TraceProbeOutput {
                            sequence: probe.sequence,
                            hop_limit: probe.hop_limit,
                            attempt: probe.attempt,
                            strategy: probe.strategy.to_string(),
                            destination: probe.destination,
                            destination_port: probe.destination_port,
                            status: probe.status.into(),
                            response_kind: probe.response_kind.map(Into::into),
                            responder: probe.responder,
                            sent_at: probe.sent_at.try_into()?,
                            received_at: probe
                                .received_at
                                .map(OutputTimestamp::try_from)
                                .transpose()?,
                            latency: probe.latency,
                            frame: probe
                                .response
                                .map(FrameOutput::try_from_frame)
                                .transpose()?,
                            reason: probe.reason,
                        })
                    })
                    .collect::<Result<Vec<_>, OutputContractError>>()?;
                Ok(TraceHopOutput {
                    hop_limit: hop.hop_limit,
                    probes: probe_outputs,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let undecoded_outputs = undecoded
            .into_iter()
            .map(|evidence| {
                Ok(TraceUndecodedOutput {
                    hop_limit: evidence.hop_limit,
                    frame: FrameOutput::try_from_frame(evidence.frame)?,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let operation_stats = OperationStats {
            packets_attempted: stats.packets_attempted,
            packets_completed: stats.packets_completed,
            bytes: stats.bytes,
            elapsed: stats.elapsed,
            capture: stats.capture.into(),
        };
        Ok((
            Self {
                target,
                resolved_addresses,
                destination,
                strategy: strategy.to_string(),
                destination_port,
                hops: hop_outputs,
                undecoded: undecoded_outputs,
                completion: completion.into(),
            },
            diagnostics,
            operation_stats,
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum TracerouteStreamCommandResult {
    Hop {
        target: String,
        destination: IpAddr,
        hop: TraceHopOutput,
    },
    Undecoded {
        hop_limit: u8,
        frame: FrameOutput,
    },
    Complete {
        target: String,
        resolved_addresses: Vec<IpAddr>,
        destination: IpAddr,
        strategy: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        destination_port: Option<u16>,
        completion: TraceCompletionReason,
    },
}
