#[cfg(test)]
mod tests {
    use std::convert::Infallible;
    use std::io::Cursor;
    use std::time::{SystemTime, UNIX_EPOCH};

    use bytes::Bytes;

    use super::*;
    use crate::capture::Writer;

    #[test]
    fn timing_is_bounded_and_validated() {
        let previous = UNIX_EPOCH + Duration::from_secs(1);
        let current = previous + Duration::from_millis(250);
        assert_eq!(
            ReplayTiming::Original
                .delay_between(previous, current)
                .unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            ReplayTiming::Scaled(2.0)
                .delay_between(previous, current)
                .unwrap(),
            Duration::from_millis(500)
        );
        assert_eq!(
            ReplayTiming::FixedRate(4.0)
                .delay_between(previous, current)
                .unwrap(),
            Duration::from_millis(250)
        );
        assert_eq!(
            ReplayTiming::Immediate
                .delay_between(previous, current)
                .unwrap(),
            Duration::ZERO
        );
        let error = ReplayTiming::Scaled(0.0)
            .delay_between(previous, current)
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "invalid replay timing: invalid replay scaled value 0"
        );
        assert_eq!(error.classification().code, "cli.replay_limit");

        assert!(ReplayTiming::FixedRate(f64::MAX)
            .delay_between(previous, current)
            .is_err());
        assert!(ReplayTiming::Scaled(f64::MIN_POSITIVE)
            .delay_between(previous, current)
            .is_err());
        assert_eq!(
            ReplayTiming::Scaled(f64::MIN_POSITIVE)
                .delay_between(previous, previous)
                .unwrap(),
            Duration::ZERO
        );
    }

    #[test]
    fn system_authorizer_checks_wire_destinations_before_decoding() {
        let mut ipv4 = vec![0_u8; 20];
        ipv4[0] = 0x45;
        ipv4[16..20].copy_from_slice(&[8, 8, 8, 8]);
        let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, ipv4).unwrap();
        assert_eq!(
            replay_wire_policy(&frame).unwrap().0,
            [IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]
        );
        let registry = Arc::new(crate::protocol::internal::default_registry().unwrap());
        let mut authorizer = SystemAuthorizer::new(
            crate::client::policy::Policy::default(),
            Arc::clone(&registry),
            true,
        );
        let error = authorizer.authorize(&frame, LinkMode::Layer3).unwrap_err();
        assert_eq!(error.classification().code, "policy.public_destination");

        for mut unsupported in [vec![0_u8; 48], vec![0_u8; 40]] {
            unsupported[0] = 0x60;
            unsupported[6] = 43;
            unsupported[24..40].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
            if unsupported.len() == 48 {
                unsupported[40] = 59;
                unsupported[42] = 0;
            }
            let frame = Frame::new(SystemTime::UNIX_EPOCH, LinkType::RAW, unsupported).unwrap();
            assert!(replay_wire_policy(&frame).unwrap().1);
            let mut authorizer = SystemAuthorizer::new(
                crate::client::policy::Policy::default(),
                Arc::clone(&registry),
                true,
            );
            let error = authorizer.authorize(&frame, LinkMode::Layer3).unwrap_err();
            assert_eq!(
                error.classification().code,
                "capability.replay_routing_header"
            );
        }
    }

    #[derive(Default)]
    struct Allow {
        calls: usize,
        deny: bool,
    }

    impl ReplayAuthorizer for Allow {
        fn authorize(
            &mut self,
            _frame: &Frame,
            _mode: LinkMode,
        ) -> Result<(), ReplayAuthorizationError> {
            self.calls += 1;
            if self.deny {
                Err(ReplayAuthorizationError::new(
                    "denied by test policy",
                    Classification::new("policy.test", Kind::Policy, None),
                    Vec::new(),
                ))
            } else {
                Ok(())
            }
        }
    }

    #[derive(Default)]
    struct Transmitter {
        calls: usize,
        partial: bool,
        omit_evidence: bool,
        wrong_interface: bool,
    }

    impl ReplayTransmitter for Transmitter {
        fn validate_interface(
            &mut self,
            interface: &InterfaceId,
            _mode: LinkMode,
            _frame: &Frame,
        ) -> Result<InterfaceId, LiveIoError> {
            Ok(interface.clone())
        }

        fn transmit(
            &mut self,
            _interface: &InterfaceId,
            _mode: LinkMode,
            frame: &Frame,
        ) -> Result<ReplayTransmission, LiveIoError> {
            self.calls += 1;
            Ok(ReplayTransmission {
                interface: if self.wrong_interface {
                    InterfaceId {
                        name: "other0".to_owned(),
                        index: _interface.index + 1,
                    }
                } else {
                    _interface.clone()
                },
                report: IoSendReport {
                    bytes_sent: if self.partial {
                        frame.bytes.len().saturating_sub(1)
                    } else {
                        frame.bytes.len()
                    },
                    wire_bytes: (!self.omit_evidence).then(|| frame.bytes.clone()),
                },
            })
        }
    }

    #[derive(Default)]
    struct Clock(Vec<Duration>);

    impl WorkflowClock for Clock {
        type Error = Infallible;

        fn sleep(&mut self, delay: Duration) -> Result<(), Self::Error> {
            self.0.push(delay);
            Ok(())
        }
    }

    fn interface() -> InterfaceId {
        InterfaceId {
            name: "test0".to_owned(),
            index: 7,
        }
    }

    fn capture(link_type: LinkType, frames: &[(Duration, &[u8])]) -> Reader<Cursor<Vec<u8>>> {
        let mut writer = Writer::pcap(Vec::new(), link_type).unwrap();
        for (timestamp, bytes) in frames {
            writer
                .write_frame(
                    &Frame::new(UNIX_EPOCH + *timestamp, link_type, bytes.to_vec()).unwrap(),
                )
                .unwrap();
        }
        Reader::new(Cursor::new(writer.into_inner())).unwrap()
    }

    fn options(timing: ReplayTiming) -> ReplayOptions {
        ReplayOptions {
            interface: interface(),
            link_mode: LinkMode::Auto,
            timing,
            limits: ReplayLimits::default(),
        }
    }

    #[test]
    fn replay_is_streaming_timed_and_exact() {
        let mut reader = capture(
            LinkType::ETHERNET,
            &[
                (Duration::from_secs(1), &[1, 2]),
                (Duration::from_millis(1_250), &[3, 4, 5]),
            ],
        );
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let mut evidence = Vec::new();
        let summary = replay_capture(
            &mut reader,
            &options(ReplayTiming::Scaled(2.0)),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |event| {
                evidence.push(event);
                Ok(())
            },
        )
        .unwrap();

        assert_eq!(clock.0, [Duration::ZERO, Duration::from_millis(500)]);
        assert_eq!(authorizer.calls, 2);
        assert_eq!(transmitter.calls, 2);
        assert_eq!(summary.frames_attempted, 2);
        assert_eq!(summary.frames_completed, 2);
        assert_eq!(summary.bytes_completed, 5);
        assert_eq!(summary.scheduled_duration, Duration::from_millis(500));
        assert_eq!(evidence[1].frame.bytes, Bytes::from_static(&[3, 4, 5]));
        assert_eq!(evidence[1].link_mode, LinkMode::Layer2);
    }

    #[test]
    fn policy_denial_precedes_delay_and_transmission() {
        let mut reader = capture(LinkType::ETHERNET, &[(Duration::ZERO, &[1])]);
        let mut authorizer = Allow {
            deny: true,
            ..Allow::default()
        };
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &options(ReplayTiming::Immediate),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ReplayError::Authorization { sequence: 0, .. }
        ));
        assert_eq!(error.classification().code, "policy.test");
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 0);
        assert!(clock.0.is_empty());
    }

    #[test]
    fn unsupported_roots_and_explicit_mode_mismatches_are_typed() {
        for (link_type, requested, expected_code) in [
            (
                LinkType::NULL,
                LinkMode::Auto,
                "capability.replay_link_type",
            ),
            (
                LinkType::ETHERNET,
                LinkMode::Layer3,
                "capability.replay_link_type",
            ),
        ] {
            let mut reader = capture(link_type, &[(Duration::ZERO, &[1])]);
            let mut request = options(ReplayTiming::Immediate);
            request.link_mode = requested;
            let mut authorizer = Allow::default();
            let mut transmitter = Transmitter::default();
            let mut clock = Clock::default();
            let error = replay_capture(
                &mut reader,
                &request,
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |_| Ok(()),
            )
            .unwrap_err();
            assert_eq!(error.classification().code, expected_code);
            assert_eq!(authorizer.calls, 0);
            assert_eq!(transmitter.calls, 0);
        }

        let mut writer = Writer::pcapng(Vec::new()).unwrap();
        let ethernet = writer.add_interface(LinkType::ETHERNET).unwrap();
        let null = writer.add_interface(LinkType::NULL).unwrap();
        let mut first = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, vec![1]).unwrap();
        first.interface = Some(ethernet);
        let mut second = Frame::new(UNIX_EPOCH, LinkType::NULL, vec![2]).unwrap();
        second.interface = Some(null);
        writer.write_frame(&first).unwrap();
        writer.write_frame(&second).unwrap();
        let mut reader = Reader::new(Cursor::new(writer.into_inner())).unwrap();
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &options(ReplayTiming::Immediate),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert_eq!(error.sequence(), Some(1));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 1);
    }

    #[test]
    fn aggregate_limits_use_checked_arithmetic_before_the_next_send() {
        let mut reader = capture(
            LinkType::ETHERNET,
            &[(Duration::ZERO, &[1]), (Duration::ZERO, &[2])],
        );
        let mut request = options(ReplayTiming::Immediate);
        request.limits.max_frames = 1;
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &request,
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ReplayError::FrameLimit {
                sequence: 1,
                actual: 2,
                limit: 1
            }
        ));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 1);

        let mut reader = capture(
            LinkType::ETHERNET,
            &[(Duration::ZERO, &[1, 2]), (Duration::ZERO, &[3])],
        );
        let mut request = options(ReplayTiming::Immediate);
        request.limits.max_bytes = 2;
        request.limits.max_frame_bytes = 2;
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &request,
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(
            error,
            ReplayError::ByteLimit {
                sequence: 1,
                actual: 3,
                limit: 2
            }
        ));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 1);
    }

    #[test]
    fn replay_duration_limit_precedes_policy_clock_and_next_send() {
        let mut reader = capture(
            LinkType::ETHERNET,
            &[
                (Duration::ZERO, &[1]),
                (MAX_REPLAY_DURATION + Duration::from_millis(1), &[2]),
            ],
        );
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &options(ReplayTiming::Original),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, ReplayError::DurationLimit { .. }));
        assert_eq!(authorizer.calls, 1);
        assert_eq!(transmitter.calls, 1);
        assert_eq!(clock.0, [Duration::ZERO]);
    }

    #[test]
    fn partial_send_and_missing_wire_evidence_are_failures() {
        for transmitter in [
            Transmitter {
                partial: true,
                ..Transmitter::default()
            },
            Transmitter {
                omit_evidence: true,
                ..Transmitter::default()
            },
        ] {
            let mut reader = capture(LinkType::ETHERNET, &[(Duration::ZERO, &[1, 2])]);
            let mut authorizer = Allow::default();
            let mut transmitter = transmitter;
            let mut clock = Clock::default();
            let error = replay_capture(
                &mut reader,
                &options(ReplayTiming::Immediate),
                &mut authorizer,
                &mut transmitter,
                &mut clock,
                |_| Ok(()),
            )
            .unwrap_err();
            assert!(matches!(
                error,
                ReplayError::Transmission { .. } | ReplayError::InvalidEvidence { .. }
            ));
        }
    }

    #[test]
    fn transmission_interface_must_match_the_validated_interface() {
        let mut reader = capture(LinkType::ETHERNET, &[(Duration::ZERO, &[1, 2])]);
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter {
            wrong_interface: true,
            ..Transmitter::default()
        };
        let mut emitted = false;
        let error = replay_capture(
            &mut reader,
            &options(ReplayTiming::Immediate),
            &mut authorizer,
            &mut transmitter,
            &mut Clock::default(),
            |_| {
                emitted = true;
                Ok(())
            },
        )
        .unwrap_err();

        assert!(matches!(
            error,
            ReplayError::InvalidEvidence { sequence: 0, .. }
        ));
        assert!(!emitted);
    }

    #[test]
    fn malformed_tail_is_not_clean_end_of_stream() {
        let mut writer = Writer::pcap(Vec::new(), LinkType::ETHERNET).unwrap();
        writer
            .write_frame(&Frame::new(SystemTime::UNIX_EPOCH, LinkType::ETHERNET, vec![1]).unwrap())
            .unwrap();
        let mut bytes = writer.into_inner();
        bytes.extend_from_slice(&[0_u8; 8]);
        let mut reader = Reader::new(Cursor::new(bytes)).unwrap();
        let mut authorizer = Allow::default();
        let mut transmitter = Transmitter::default();
        let mut clock = Clock::default();
        let error = replay_capture(
            &mut reader,
            &options(ReplayTiming::Immediate),
            &mut authorizer,
            &mut transmitter,
            &mut clock,
            |_| Ok(()),
        )
        .unwrap_err();
        assert!(matches!(error, ReplayError::Capture { sequence: 1, .. }));
    }
}
