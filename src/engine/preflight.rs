// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::domain::report::PreflightView;
use crate::domain::spec::PacketSpec;
use crate::network::io::sender::{
    emission_accounting, LinkType, NetworkTarget, SenderResult, TransmissionPlan,
};
use crate::output::OutputController;

impl PreflightView {
    pub(crate) fn try_from_plan(plan: &TransmissionPlan) -> SenderResult<Self> {
        let accounting =
            emission_accounting(&plan.transmit, plan.policy, plan.summary.frame_count as u64)?;
        let send_mode = if accounting.attempts.is_some() {
            "finite"
        } else {
            "unbounded"
        };

        Ok(Self {
            destination: planned_destination(plan),
            selected_destination_ip: plan.selection.destination_ip.to_string(),
            destination_reason: plan.selection.destination_reason.as_str(),
            destination_family: planned_destination_family(plan),
            interface: plan.interface.name.clone(),
            interface_reason: plan.selection.interface_reason.as_str(),
            source_ip: plan.selection.source_ip.to_string(),
            source_reason: plan.selection.source_reason.as_str(),
            mode: planned_mode(plan),
            transport: plan.summary.transport,
            count: accounting.attempts,
            attempts: accounting.attempts,
            units_per_attempt: accounting.units_per_attempt,
            total_emitted_units: accounting.total_emitted_units,
            send_mode,
            frame_count: plan.summary.frame_count,
            largest_frame_len: plan.summary.largest_frame_len,
            transmit: plan.transmit.clone(),
        })
    }
}

impl OutputController {
    pub fn emit_preflight_summary(
        &self,
        spec: &PacketSpec,
        plan: &TransmissionPlan,
    ) -> anyhow::Result<()> {
        let view = PreflightView::try_from_plan(plan)?;
        self.emit_preflight_view_summary(spec, &view)
    }
}

fn planned_destination_family(plan: &TransmissionPlan) -> &'static str {
    match &plan.destination {
        NetworkTarget::Ipv4(_) => "IPv4",
        NetworkTarget::Ipv6(_) => "IPv6",
    }
}

fn planned_destination(plan: &TransmissionPlan) -> String {
    match &plan.destination {
        NetworkTarget::Ipv4(addr) => addr.to_string(),
        NetworkTarget::Ipv6(addr) => addr.to_string(),
    }
}

fn planned_mode(plan: &TransmissionPlan) -> &'static str {
    if plan.transmit.is_layer3() || matches!(&plan.link_type, LinkType::Ipv4 | LinkType::Ipv6) {
        "L3"
    } else {
        "L2"
    }
}
