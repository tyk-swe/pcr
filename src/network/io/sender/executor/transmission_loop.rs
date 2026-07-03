// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::network::sender::error::Result;
use crate::util::telemetry;

use super::super::control::{determine_send_mode, SendMode};
use super::super::types::NetworkTransmissionPlan;

pub(crate) fn run_transmission_loop<S, R, I, C>(
    plan: &NetworkTransmissionPlan,
    mut send_frame: S,
    mut record_packet: R,
    on_infinite_start: I,
    on_complete: C,
) -> Result<()>
where
    S: FnMut(&[u8]) -> Result<()>,
    R: FnMut(&[u8]) -> Result<()>,
    I: FnOnce(),
    C: FnOnce(u64),
{
    let mode = determine_send_mode(&plan.transmit, plan.policy)?;

    if matches!(mode, SendMode::Infinite) {
        on_infinite_start();
    }

    let (frames_counter, bytes_counter) =
        telemetry::get_frame_sent_counters(plan.link_type.as_str(), plan.summary.transport);

    let mut iterations: u64 = 0;
    let mut transmitted: u64 = 0;
    let interval = plan.transmit.interval;
    let rate_delay = plan.policy.rate_delay();
    let mut last_send: Option<Instant> = None;

    loop {
        for frame in &plan.frames {
            wait_for_rate_slot(rate_delay, &mut last_send);
            send_frame(frame)?;
            record_packet(frame)?;
            frames_counter.inc();
            bytes_counter.inc_by(frame.len() as u64);
            transmitted += 1;
        }
        iterations += 1;

        if let SendMode::Finite(limit) = mode {
            if iterations >= limit {
                on_complete(transmitted);
                break;
            }
        }

        if plan.transmit.flood {
            continue;
        }

        if let Some(delay) = interval {
            sleep(delay);
        }
    }
    Ok(())
}

fn wait_for_rate_slot(rate_delay: Option<Duration>, last_send: &mut Option<Instant>) {
    let Some(delay) = rate_delay else {
        return;
    };

    if let Some(last) = *last_send {
        let elapsed = last.elapsed();
        if elapsed < delay {
            sleep(delay - elapsed);
        }
    }

    *last_send = Some(Instant::now());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::policy::{TrafficBudget, TransmissionPolicy};
    use crate::domain::spec::{LoggingSpec, TransmissionSpec};
    use crate::network::sender::error::{ExecutorError, SenderError};
    use crate::network::sender::types::{
        DestinationSelectionReason, InterfaceSelectionReason, LinkType, NetworkTarget,
        PlanningMode, SelectionMetadata, SourceSelectionReason, TransmissionSummary,
    };
    use pnet::datalink::{MacAddr, NetworkInterface};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use std::net::{IpAddr, Ipv4Addr};

    fn interface() -> NetworkInterface {
        NetworkInterface {
            name: "eth-test".to_string(),
            description: String::new(),
            index: 1,
            mac: Some(MacAddr::new(0x02, 0, 0, 0, 0, 1)),
            ips: vec!["192.0.2.5/24".parse().unwrap()],
            flags: libc::IFF_UP as u32,
        }
    }

    fn plan(frames: Vec<Vec<u8>>, count: Option<u64>) -> NetworkTransmissionPlan {
        NetworkTransmissionPlan {
            frames,
            link_type: LinkType::Ipv4,
            transmit: TransmissionSpec {
                count,
                ..Default::default()
            },
            destination: NetworkTarget::Ipv4(Ipv4Addr::new(192, 0, 2, 10)),
            interface: interface(),
            selection: SelectionMetadata {
                selected_interface: "eth-test".to_string(),
                interface_reason: InterfaceSelectionReason::ExplicitInterface,
                source_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 5)),
                source_reason: SourceSelectionReason::ExplicitSourceIp,
                destination_ip: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
                destination_reason: DestinationSelectionReason::TargetLiteral,
            },
            protocol: IpNextHeaderProtocols::Udp,
            summary: TransmissionSummary {
                payload_len: 0,
                largest_frame_len: 0,
                frame_count: 1,
                transport: "udp",
            },
            logging: LoggingSpec::default(),
            mode: PlanningMode::Live,
            policy: TransmissionPolicy {
                budget: TrafficBudget {
                    max_rate_per_sec: 0,
                    ..Default::default()
                },
                ..Default::default()
            },
        }
    }

    #[test]
    fn run_transmission_loop_sends_default_single_iteration() {
        let plan = plan(vec![vec![1, 2, 3]], None);
        let mut sent = Vec::new();
        let mut recorded = Vec::new();
        let mut completed = None;

        run_transmission_loop(
            &plan,
            |frame| {
                sent.push(frame.to_vec());
                Ok(())
            },
            |frame| {
                recorded.push(frame.to_vec());
                Ok(())
            },
            || panic!("finite send should not report infinite start"),
            |count| completed = Some(count),
        )
        .unwrap();

        assert_eq!(sent, [vec![1, 2, 3]]);
        assert_eq!(recorded, sent);
        assert_eq!(completed, Some(1));
    }

    #[test]
    fn run_transmission_loop_honors_finite_count() {
        let plan = plan(vec![vec![1]], Some(3));
        let mut sends = 0;

        run_transmission_loop(
            &plan,
            |_| {
                sends += 1;
                Ok(())
            },
            |_| Ok(()),
            || panic!("finite send should not report infinite start"),
            |_| {},
        )
        .unwrap();

        assert_eq!(sends, 3);
    }

    #[test]
    fn run_transmission_loop_propagates_send_error_before_recording() {
        let plan = plan(vec![vec![1]], Some(1));
        let mut recorded = false;
        let err = run_transmission_loop(
            &plan,
            |_| Err(ExecutorError::DatalinkChannelExhausted.into()),
            |_| {
                recorded = true;
                Ok(())
            },
            || {},
            |_| {},
        )
        .unwrap_err();

        assert!(!recorded);
        assert!(matches!(
            err,
            SenderError::Executor(ExecutorError::DatalinkChannelExhausted)
        ));
    }

    #[test]
    fn run_transmission_loop_propagates_record_error_after_send() {
        let plan = plan(vec![vec![1]], Some(1));
        let mut sent = false;
        let err = run_transmission_loop(
            &plan,
            |_| {
                sent = true;
                Ok(())
            },
            |_| Err(ExecutorError::DatalinkChannelExhausted.into()),
            || {},
            |_| {},
        )
        .unwrap_err();

        assert!(sent);
        assert!(matches!(
            err,
            SenderError::Executor(ExecutorError::DatalinkChannelExhausted)
        ));
    }

    #[test]
    fn run_transmission_loop_completion_callback_receives_transmitted_count() {
        let plan = plan(vec![vec![1], vec![2]], Some(2));
        let mut completed = None;

        run_transmission_loop(
            &plan,
            |_| Ok(()),
            |_| Ok(()),
            || {},
            |count| completed = Some(count),
        )
        .unwrap();

        assert_eq!(completed, Some(4));
    }

    #[test]
    fn run_transmission_loop_rejects_zero_count_before_sending() {
        let plan = plan(vec![vec![1]], Some(0));
        let err = run_transmission_loop(
            &plan,
            |_| panic!("zero count should fail before sending"),
            |_| Ok(()),
            || {},
            |_| {},
        )
        .unwrap_err();

        assert!(matches!(
            err,
            SenderError::SendControl(
                crate::domain::transmission::SendControlError::CountMustBePositive
            )
        ));
    }

    #[test]
    fn run_transmission_loop_iterates_multiple_frames_in_order() {
        let plan = plan(vec![vec![1], vec![2]], Some(2));
        let mut sent = Vec::new();

        run_transmission_loop(
            &plan,
            |frame| {
                sent.push(frame.to_vec());
                Ok(())
            },
            |_| Ok(()),
            || {},
            |_| {},
        )
        .unwrap();

        assert_eq!(sent, [vec![1], vec![2], vec![1], vec![2]]);
    }
}
