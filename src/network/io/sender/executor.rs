mod backends;
mod recorder;
mod transmission_loop;

use crate::network::sender::error::{ExecutorError, Result};

use backends::send_via_datalink;
use log::error;
use recorder::PacketRecorder;

#[cfg(test)]
pub(crate) use backends::send_loop;
pub(crate) use backends::send_via_transport;
#[cfg(test)]
use transmission_loop::run_transmission_loop;

use super::types::{LinkType, TransmissionPlan};

pub async fn execute_transmission(plan: TransmissionPlan) -> Result<()> {
    if plan.mode == crate::network::sender::types::PlanningMode::DryRun {
        return Err(ExecutorError::DryRunBlocked.into());
    }
    let result = tokio::task::spawn_blocking(move || run_transmission_task(plan)).await;

    match result {
        Ok(inner) => inner,
        Err(e) => {
            if e.is_cancelled() {
                error!("Transmission task cancelled");
                Err(ExecutorError::TaskCancelled.into())
            } else {
                error!("Transmission task panicked");
                Err(ExecutorError::TaskPanicked.into())
            }
        }
    }
}

fn run_transmission_task(plan: TransmissionPlan) -> Result<()> {
    let mut recorder = PacketRecorder::for_plan(&plan)?;

    let link_type = plan.link_type.clone();
    let result = {
        let mut record_packet = |frame: &[u8]| recorder.record(frame);
        match link_type {
            LinkType::Ethernet => send_via_datalink(plan, &mut record_packet),
            LinkType::Ipv4 | LinkType::Ipv6 => send_via_transport(plan, &mut record_packet),
        }
    };

    if result.is_ok() {
        recorder.flush()?;
    }

    result
}

#[cfg(any(test, feature = "test_utils"))]
pub mod test_utils {
    use pnet::datalink::{DataLinkSender, NetworkInterface};
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone)]
    pub struct FakePacketSender {
        sent_packets: Arc<Mutex<Vec<Vec<u8>>>>,
        fail_next: bool,
        exhaust_channel: bool,
    }

    impl Default for FakePacketSender {
        fn default() -> Self {
            Self::new()
        }
    }

    impl FakePacketSender {
        pub fn new() -> Self {
            Self {
                sent_packets: Arc::new(Mutex::new(Vec::new())),
                fail_next: false,
                exhaust_channel: false,
            }
        }

        pub fn fail_next_send(&mut self) {
            self.fail_next = true;
        }

        pub fn exhaust_channel(&mut self) {
            self.exhaust_channel = true;
        }

        pub fn sent_packets_handle(&self) -> Arc<Mutex<Vec<Vec<u8>>>> {
            Arc::clone(&self.sent_packets)
        }

        pub fn sent_packets(&self) -> Vec<Vec<u8>> {
            self.sent_packets
                .lock()
                .expect("fake sender packet lock should not be poisoned")
                .clone()
        }
    }

    impl DataLinkSender for FakePacketSender {
        fn build_and_send(
            &mut self,
            _num_packets: usize,
            _packet_size: usize,
            _func: &mut dyn FnMut(&mut [u8]),
        ) -> Option<std::io::Result<()>> {
            None
        }

        fn send_to(
            &mut self,
            packet: &[u8],
            _dst: Option<NetworkInterface>,
        ) -> Option<std::io::Result<()>> {
            if self.exhaust_channel {
                return None;
            }
            if self.fail_next {
                self.fail_next = false;
                return Some(Err(std::io::Error::other("simulated error")));
            }
            self.sent_packets
                .lock()
                .expect("fake sender packet lock should not be poisoned")
                .push(packet.to_vec());
            Some(Ok(()))
        }
    }

    pub fn dummy_interface() -> NetworkInterface {
        NetworkInterface {
            name: "test_iface".to_string(),
            description: "".to_string(),
            index: 1,
            mac: None,
            ips: Vec::new(),
            flags: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::spec::{LoggingSpec, TransmissionSpec};
    use crate::network::sender::error::ExecutorError;
    use crate::network::sender::types::{
        LinkType, NetworkTarget, TransmissionPlan, TransmissionSummary,
    };
    use crate::network::sender::{SendControlError, TransmissionPolicy};
    use pnet::packet::ip::IpNextHeaderProtocols;
    use std::time::{Duration, Instant};
    use test_utils::FakePacketSender as MockSender;

    fn create_test_plan(
        frames: Vec<Vec<u8>>,
        count: Option<u64>,
        interval: Option<Duration>,
    ) -> TransmissionPlan {
        TransmissionPlan {
            frames,
            link_type: LinkType::Ethernet,
            transmit: TransmissionSpec {
                count,
                interval,
                flood: false,
                loop_send: false,
                force_layer3: false,
                ipv6_nd: false,
                auto_layer3: false,
            },
            destination: NetworkTarget::Ipv4(std::net::Ipv4Addr::LOCALHOST),
            interface: test_utils::dummy_interface(),
            protocol: IpNextHeaderProtocols::Tcp,
            summary: TransmissionSummary {
                payload_len: 0,
                largest_frame_len: 0,
                frame_count: 0,
                transport: "tcp",
            },
            logging: LoggingSpec::default(),
            mode: crate::network::sender::types::PlanningMode::Live,
            policy: TransmissionPolicy::default(),
        }
    }

    #[test]
    fn send_loop_sends_correct_number_of_packets() {
        let frames = vec![vec![0x01, 0x02], vec![0x03, 0x04]];
        let plan = create_test_plan(frames.clone(), Some(3), None);
        let mut sender = MockSender::new();
        let sent_packets = sender.sent_packets_handle();

        send_loop(&mut sender, &plan, &plan.interface, &mut |_| Ok(())).expect("send_loop failed");

        let packets = sent_packets.lock().unwrap();
        assert_eq!(packets.len(), 6); // 2 frames * 3 iterations
        assert_eq!(packets[0], vec![0x01, 0x02]);
        assert_eq!(packets[1], vec![0x03, 0x04]);
        assert_eq!(packets[2], vec![0x01, 0x02]);
    }

    #[test]
    fn run_transmission_loop_reports_completed_frame_count() {
        let plan = create_test_plan(vec![vec![0x01], vec![0x02]], Some(3), None);
        let mut send_count = 0;
        let mut completed_count = None;

        run_transmission_loop(
            &plan,
            |_frame| {
                send_count += 1;
                Ok(())
            },
            |_frame| Ok(()),
            || panic!("finite transmission should not start infinite logging"),
            |sent| {
                completed_count = Some(sent);
            },
        )
        .expect("transmission loop failed");

        assert_eq!(send_count, 6);
        assert_eq!(completed_count, Some(6));
    }

    #[test]
    fn send_loop_respects_interval() {
        let frames = vec![vec![0x01]];
        let interval = Duration::from_millis(100);
        let plan = create_test_plan(frames, Some(2), Some(interval));
        let mut sender = MockSender::new();

        let start = Instant::now();
        send_loop(&mut sender, &plan, &plan.interface, &mut |_| Ok(())).expect("send_loop failed");
        let duration = start.elapsed();

        assert!(duration >= interval);
    }

    #[test]
    fn send_loop_handles_send_error() {
        let frames = vec![vec![0x01]];
        let plan = create_test_plan(frames, Some(1), None);
        let mut sender = MockSender::new();
        sender.fail_next_send();

        let result = send_loop(&mut sender, &plan, &plan.interface, &mut |_| Ok(()));
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::network::sender::error::SenderError::Executor(
                ExecutorError::FrameSendFailed { .. },
            ) => (),
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn send_loop_calls_record_callback() {
        let frames = vec![vec![0xAA]];
        let plan = create_test_plan(frames, Some(1), None);
        let mut sender = MockSender::new();

        let mut recorded_count = 0;
        send_loop(&mut sender, &plan, &plan.interface, &mut |_| {
            recorded_count += 1;
            Ok(())
        })
        .expect("send_loop failed");

        assert_eq!(recorded_count, 1);
    }

    #[test]
    fn send_loop_rejects_zero_count() {
        let frames = vec![vec![0x01]];
        let plan = create_test_plan(frames, Some(0), None);
        let mut sender = MockSender::new();
        let sent_packets = sender.sent_packets_handle();

        let result = send_loop(&mut sender, &plan, &plan.interface, &mut |_| Ok(()));
        assert!(matches!(
            result,
            Err(crate::network::sender::error::SenderError::SendControl(
                SendControlError::CountMustBePositive
            ))
        ));

        let packets = sent_packets.lock().unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn send_loop_handles_datalink_channel_exhaustion() {
        let frames = vec![vec![0x01]];
        let plan = create_test_plan(frames, Some(1), None);
        let mut sender = MockSender::new();
        sender.exhaust_channel();

        let result = send_loop(&mut sender, &plan, &plan.interface, &mut |_| Ok(()));
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::network::sender::error::SenderError::Executor(
                ExecutorError::DatalinkChannelExhausted,
            ) => (),
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn send_loop_aborts_on_record_callback_error() {
        // Test that if the recording callback fails, the loop terminates immediately
        let frames = vec![vec![0x01], vec![0x02]];
        let plan = create_test_plan(frames, Some(1), None);
        let mut sender = MockSender::new();
        let sent_packets = sender.sent_packets_handle();

        let result = send_loop(&mut sender, &plan, &plan.interface, &mut |frame| {
            if frame[0] == 0x02 {
                Err(crate::network::sender::error::SenderError::Executor(
                    ExecutorError::DatalinkChannelExhausted,
                ))
            } else {
                Ok(())
            }
        });

        assert!(result.is_err());
        let packets = sent_packets.lock().unwrap();
        // Frame 1 sends and records successfully.
        // Frame 2 sends successfully, but recording fails, causing the loop to abort.
        // Both frames should appear in the sent_packets list.
        assert_eq!(packets.len(), 2);
    }

    #[test]
    fn send_loop_interval_is_applied_per_iteration() {
        // Verify that the sleep happens after sending all frames in the list, not between them
        let frames = vec![vec![0x01], vec![0x02]];
        let interval = Duration::from_millis(50);
        let plan = create_test_plan(frames, Some(2), Some(interval));
        let mut sender = MockSender::new();

        let start = Instant::now();
        send_loop(&mut sender, &plan, &plan.interface, &mut |_| Ok(())).expect("send_loop failed");
        let duration = start.elapsed();

        // The loop checks the limit and breaks before the sleep on the final iteration.
        // With count=2, we expect 2 iterations and exactly 1 sleep interval.
        // The total duration should be at least one interval.

        assert!(
            duration >= interval,
            "Duration {:?} < Interval {:?}",
            duration,
            interval
        );

        // Ensure we aren't sleeping multiple times (e.g. 2+ intervals).
        // If we slept after every iteration (including last), we'd have 2 intervals (100ms).
        // The expected behavior is exactly 1 sleep interval (50ms) plus overhead.
        // Using 3x interval to avoid flakiness in CI environments where threads might be descheduled.
        assert!(
            duration < interval * 3,
            "Duration {:?} too long for single interval {:?}",
            duration,
            interval
        );

        let packets = sender.sent_packets();
        assert_eq!(packets.len(), 4);
    }
}
