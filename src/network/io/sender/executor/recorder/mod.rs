// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use crate::network::sender::error::Result;

use super::super::types::NetworkTransmissionPlan;

mod writer;

pub(super) struct PacketRecorder {
    writer: writer::CaptureWriter,
}

impl PacketRecorder {
    pub(super) fn for_plan(plan: &NetworkTransmissionPlan) -> Result<Self> {
        Ok(Self {
            writer: writer::CaptureWriter::for_plan(plan)?,
        })
    }

    pub(super) fn record(&mut self, frame: &[u8]) -> Result<()> {
        self.writer.record(frame)
    }

    pub(super) fn flush(&mut self) -> Result<()> {
        self.writer.flush()
    }
}

#[cfg(all(test, not(feature = "pcap")))]
mod tests {
    use std::net::Ipv4Addr;
    use std::path::PathBuf;

    use pnet::datalink::NetworkInterface;
    use pnet::packet::ip::IpNextHeaderProtocol;

    use super::*;
    use crate::domain::policy::TrafficPolicy;
    use crate::domain::spec::{LoggingSpec, TransmissionSpec};
    use crate::domain::transmission::{
        DestinationSelectionReason, InterfaceSelectionReason, PlanningMode, SourceSelectionReason,
        TransmissionLinkType, TransmissionSelection, TransmissionSummary, TransmissionTarget,
    };
    use crate::network::sender::error::SenderError;

    fn plan_with_pcap_write(pcap_write: Option<PathBuf>) -> NetworkTransmissionPlan {
        NetworkTransmissionPlan {
            frames: vec![vec![0, 1, 2, 3]],
            link_type: TransmissionLinkType::Ethernet,
            transmit: TransmissionSpec::default(),
            destination: TransmissionTarget::Ipv4(Ipv4Addr::LOCALHOST),
            interface: NetworkInterface {
                name: "lo".to_string(),
                description: String::new(),
                index: 1,
                mac: None,
                ips: Vec::new(),
                flags: 0,
            },
            selection: TransmissionSelection {
                selected_interface: "lo".to_string(),
                interface_reason: InterfaceSelectionReason::ExplicitInterface,
                source_ip: Ipv4Addr::LOCALHOST.into(),
                source_reason: SourceSelectionReason::ExplicitSourceIp,
                destination_ip: Ipv4Addr::LOCALHOST.into(),
                destination_reason: DestinationSelectionReason::TargetLiteral,
            },
            protocol: IpNextHeaderProtocol(17),
            summary: TransmissionSummary {
                payload_len: 0,
                largest_frame_len: 4,
                frame_count: 1,
                transport: "udp",
            },
            logging: LoggingSpec {
                pcap_write,
                ..Default::default()
            },
            mode: PlanningMode::Live,
            policy: TrafficPolicy::default(),
        }
    }

    #[test]
    fn no_pcap_recorder_without_capture_file_is_noop() {
        let mut recorder = PacketRecorder::for_plan(&plan_with_pcap_write(None)).unwrap();

        recorder.record(&[0, 1, 2, 3]).unwrap();
        recorder.flush().unwrap();
    }

    #[test]
    fn no_pcap_recorder_rejects_capture_file() {
        let err = match PacketRecorder::for_plan(&plan_with_pcap_write(Some(PathBuf::from(
            "out.pcap",
        )))) {
            Ok(_) => panic!("recorder unexpectedly accepted pcap output without pcap feature"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            SenderError::Executor(
                crate::network::sender::error::ExecutorError::PcapFeatureRequired { .. }
            )
        ));
    }
}
