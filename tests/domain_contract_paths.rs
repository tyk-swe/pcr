// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr::domain::{command, event, policy, request, spec};

#[test]
fn shared_contracts_are_public_from_domain() {
    let request = request::PacketRequest::default();
    let _command = command::EngineCommand::DryRun(request.clone());
    let _dns = command::DnsRequest::default();
    let _policy = policy::TrafficPolicy::default();
    let _plan =
        policy::TrafficPlan::new(policy::TrafficMode::Send, policy::TargetScope::Unspecified);
    let _spec = spec::PacketSpec::from_request(&request);
    let _label = event::ProtocolLabel::Unknown;
}
