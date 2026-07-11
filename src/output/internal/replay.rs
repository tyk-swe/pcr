/// Aggregate or terminal result of `replay`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplaySourceFormat {
    Pcap,
    PcapNg,
}

impl From<crate::capture::Format> for ReplaySourceFormat {
    fn from(value: crate::capture::Format) -> Self {
        match value {
            crate::capture::Format::Pcap => Self::Pcap,
            crate::capture::Format::PcapNg => Self::PcapNg,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayTimingOutput {
    Original,
    Scaled(f64),
    FixedRate(f64),
    Immediate,
}

impl From<crate::workflow::replay::Timing> for ReplayTimingOutput {
    fn from(value: crate::workflow::replay::Timing) -> Self {
        match value {
            crate::workflow::replay::Timing::Original => Self::Original,
            crate::workflow::replay::Timing::Scaled(scale) => Self::Scaled(scale),
            crate::workflow::replay::Timing::FixedRate(rate) => Self::FixedRate(rate),
            crate::workflow::replay::Timing::Immediate => Self::Immediate,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReplayInterfaceOutput {
    pub name: String,
    pub index: u32,
}

impl From<InterfaceId> for ReplayInterfaceOutput {
    fn from(value: InterfaceId) -> Self {
        Self {
            name: value.name,
            index: value.index,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayLinkMode {
    Auto,
    Layer2,
    Layer3,
}

impl From<LinkMode> for ReplayLinkMode {
    fn from(value: LinkMode) -> Self {
        match value {
            LinkMode::Auto => Self::Auto,
            LinkMode::Layer2 => Self::Layer2,
            LinkMode::Layer3 => Self::Layer3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ReplayCommandResult {
    pub source_format: ReplaySourceFormat,
    pub timing: ReplayTimingOutput,
    pub requested_interface: ReplayInterfaceOutput,
    pub requested_link_mode: ReplayLinkMode,
    pub frames_attempted: u64,
    pub frames_completed: u64,
    pub bytes_completed: u64,
    pub scheduled_duration: Duration,
    pub frames: Vec<ReplayFrameCommandResult>,
}

impl ReplayCommandResult {
    pub fn from_summary(
        summary: ReplaySummary,
        requested_interface: InterfaceId,
        requested_link_mode: LinkMode,
        frames: Vec<ReplayFrameCommandResult>,
    ) -> Self {
        Self {
            source_format: summary.source_format.into(),
            timing: summary.timing.into(),
            requested_interface: requested_interface.into(),
            requested_link_mode: requested_link_mode.into(),
            frames_attempted: summary.frames_attempted,
            frames_completed: summary.frames_completed,
            bytes_completed: summary.bytes_completed,
            scheduled_duration: summary.scheduled_duration,
            frames,
        }
    }
}

/// One frame record produced by streaming `replay` output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReplayFrameCommandResult {
    pub source_sequence: u64,
    pub interface: ReplayInterfaceOutput,
    pub link_mode: ReplayLinkMode,
    pub scheduled_delay: Duration,
    pub bytes_sent: u64,
    pub frame: FrameOutput,
    pub transmitted: bool,
}

impl ReplayFrameCommandResult {
    pub fn try_from_evidence(evidence: ReplayFrameEvidence) -> Result<Self, OutputContractError> {
        Ok(Self {
            source_sequence: evidence.source_sequence,
            interface: evidence.interface.into(),
            link_mode: evidence.link_mode.into(),
            scheduled_delay: evidence.scheduled_delay,
            bytes_sent: evidence.bytes_sent,
            frame: FrameOutput::try_from_frame(evidence.frame)?,
            transmitted: true,
        })
    }
}
