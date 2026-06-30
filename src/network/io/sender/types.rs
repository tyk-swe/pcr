// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use pnet::datalink::NetworkInterface;
use pnet::packet::ip::IpNextHeaderProtocol;

use crate::domain::policy::TransmissionPolicy;
use crate::domain::spec::{LoggingSpec, TransmissionSpec};

pub use crate::domain::transmission::{
    DestinationSelectionReason, InterfaceSelectionReason, PlanningMode, SourceSelectionReason,
    TransmissionLinkType as LinkType, TransmissionSelection as SelectionMetadata,
    TransmissionSummary, TransmissionTarget as NetworkTarget,
};

#[derive(Debug, Clone)]
pub struct TransmissionPlan {
    pub frames: Vec<Vec<u8>>,
    pub link_type: LinkType,
    pub transmit: TransmissionSpec,
    pub destination: NetworkTarget,
    pub interface: NetworkInterface,
    pub selection: SelectionMetadata,
    pub protocol: IpNextHeaderProtocol,
    pub summary: TransmissionSummary,
    pub logging: LoggingSpec,
    pub mode: PlanningMode,
    pub policy: TransmissionPolicy,
}
