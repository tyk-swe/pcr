#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Condvar, MutexGuard};
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use crate::capture::Direction;
    use crate::error::Classified;
    use crate::net::{InterfaceAddress, InterfaceFlags, IoSendReport, LiveIoError};

    type ResponseFactory = dyn Fn(&Bytes) -> Vec<Frame> + Send + Sync;

    #[derive(Default)]
    struct MockState {
        ready: bool,
        sent: Vec<Bytes>,
        planned: Vec<PlannedRoute>,
        frames: VecDeque<CapturedFrame>,
        shutdowns: usize,
    }

    #[derive(Default)]
    struct MockShared {
        state: Mutex<MockState>,
        changed: Condvar,
    }

    impl MockShared {
        fn lock(&self) -> MutexGuard<'_, MockState> {
            self.state.lock().unwrap()
        }
    }

    #[derive(Clone)]
    struct MockInterfaces(InterfaceInfo);

    impl InterfaceProvider for MockInterfaces {
        fn interfaces(&self) -> Result<Vec<InterfaceInfo>, LiveIoError> {
            Ok(vec![self.0.clone()])
        }
    }

    #[derive(Clone)]
    struct MockLayer2 {
        shared: Arc<MockShared>,
        responses: Arc<ResponseFactory>,
        pre_send_responses: usize,
        record_ingress_time: bool,
    }

    impl Layer2Io for MockLayer2 {
        fn send_layer2(&self, frame: Layer2Frame<'_>) -> Result<IoSendReport, LiveIoError> {
            let bytes = frame.bytes().clone();
            let responses = (self.responses)(&bytes);
            let mut state = self.shared.lock();
            assert!(state.ready, "capture must be ready before neighbor send");
            assert_eq!(frame.route().plan.mode, LinkMode::Layer2);
            state.sent.push(bytes.clone());
            state
                .frames
                .extend(responses.into_iter().enumerate().map(|(index, frame)| {
                    let now = Instant::now();
                    let received_at = if index < self.pre_send_responses {
                        now.checked_sub(Duration::from_secs(1)).unwrap_or(now)
                    } else {
                        now
                    };
                    if self.record_ingress_time {
                        CapturedFrame::new(frame, received_at)
                    } else {
                        CapturedFrame::without_ingress_time(frame)
                    }
                }));
            self.shared.changed.notify_all();
            Ok(IoSendReport {
                bytes_sent: bytes.len(),
                wire_bytes: Some(bytes),
            })
        }
    }

    #[derive(Clone)]
    struct MockCaptureProvider(Arc<MockShared>);

    impl CaptureProvider for MockCaptureProvider {
        type Capture = MockCaptureSession;

        fn arm_capture(
            &self,
            route: &PlannedRoute,
            limits: CaptureQueueLimits,
        ) -> Result<Self::Capture, LiveIoError> {
            limits.validate()?;
            self.0.lock().planned.push(route.clone());
            Ok(MockCaptureSession(Arc::clone(&self.0)))
        }
    }

    struct MockCaptureSession(Arc<MockShared>);

    impl CaptureSession for MockCaptureSession {
        fn wait_ready(&mut self, _timeout: Duration) -> Result<(), LiveIoError> {
            self.0.lock().ready = true;
            self.0.changed.notify_all();
            Ok(())
        }

        fn next_frame(&mut self, timeout: Duration) -> Result<Option<Frame>, LiveIoError> {
            self.next_captured_frame(timeout)
                .map(|captured| captured.map(|captured| captured.frame))
        }

        fn next_captured_frame(
            &mut self,
            timeout: Duration,
        ) -> Result<Option<CapturedFrame>, LiveIoError> {
            let mut state = self.0.lock();
            if let Some(frame) = state.frames.pop_front() {
                return Ok(Some(frame));
            }
            if timeout.is_zero() {
                return Ok(None);
            }
            let (mut state, _) = self.0.changed.wait_timeout(state, timeout).unwrap();
            Ok(state.frames.pop_front())
        }

        fn shutdown(&mut self) -> Result<(), LiveIoError> {
            let mut state = self.0.lock();
            state.ready = false;
            state.shutdowns += 1;
            Ok(())
        }

        fn statistics(&self) -> CaptureStatistics {
            CaptureStatistics::default()
        }
    }

    fn interface() -> InterfaceInfo {
        InterfaceInfo {
            id: InterfaceId {
                name: "mock0".to_owned(),
                index: 7,
            },
            description: Some("mock interface".to_owned()),
            mac_address: Some(MacAddress([0x02, 0, 0, 0, 0, 7])),
            addresses: vec![
                InterfaceAddress {
                    address: "192.0.2.7".parse().unwrap(),
                    prefix_length: 24,
                },
                InterfaceAddress {
                    address: "2001:db8::7".parse().unwrap(),
                    prefix_length: 64,
                },
            ],
            flags: InterfaceFlags {
                up: true,
                broadcast: true,
                multicast: true,
                ..InterfaceFlags::default()
            },
            mtu: Some(1_500),
            capability: LinkCapability::Layer2And3,
            link_type: LinkType::ETHERNET,
        }
    }

    fn request(source: &str, target: &str) -> NeighborRequest {
        let interface = interface();
        NeighborRequest {
            interface: interface.id,
            interface_source: source.parse().unwrap(),
            interface_mac: interface.mac_address.unwrap(),
            target: target.parse().unwrap(),
            vlan_tags: Vec::new(),
            mtu: interface.mtu.unwrap(),
            link_type: interface.link_type,
        }
    }

    fn options() -> NeighborResolutionOptions {
        NeighborResolutionOptions {
            max_attempts: 2,
            attempt_timeout: Duration::from_millis(20),
            cache_ttl: Duration::from_secs(30),
            max_cache_entries: 8,
            max_capture_queue_frames: 8,
            max_captured_bytes: 8 * 2_048,
            snap_length: 2_048,
        }
    }

    fn resolver(
        shared: Arc<MockShared>,
        responses: Arc<ResponseFactory>,
        options: NeighborResolutionOptions,
    ) -> ActiveNeighborResolver<MockInterfaces, MockLayer2, MockCaptureProvider> {
        ActiveNeighborResolver::try_new(
            MockInterfaces(interface()),
            MockLayer2 {
                shared: Arc::clone(&shared),
                responses,
                pre_send_responses: 0,
                record_ingress_time: true,
            },
            MockCaptureProvider(shared),
            options,
        )
        .unwrap()
    }

    fn resolver_with_pre_send_responses(
        shared: Arc<MockShared>,
        responses: Arc<ResponseFactory>,
        pre_send_responses: usize,
        options: NeighborResolutionOptions,
    ) -> ActiveNeighborResolver<MockInterfaces, MockLayer2, MockCaptureProvider> {
        ActiveNeighborResolver::try_new(
            MockInterfaces(interface()),
            MockLayer2 {
                shared: Arc::clone(&shared),
                responses,
                pre_send_responses,
                record_ingress_time: true,
            },
            MockCaptureProvider(shared),
            options,
        )
        .unwrap()
    }

    fn resolver_without_ingress_time(
        shared: Arc<MockShared>,
        responses: Arc<ResponseFactory>,
        options: NeighborResolutionOptions,
    ) -> ActiveNeighborResolver<MockInterfaces, MockLayer2, MockCaptureProvider> {
        ActiveNeighborResolver::try_new(
            MockInterfaces(interface()),
            MockLayer2 {
                shared: Arc::clone(&shared),
                responses,
                pre_send_responses: 0,
                record_ingress_time: false,
            },
            MockCaptureProvider(shared),
            options,
        )
        .unwrap()
    }

    fn captured(bytes: Bytes, interface: u32) -> Frame {
        let mut frame = Frame::new(UNIX_EPOCH, LinkType::ETHERNET, bytes).unwrap();
        frame.interface = Some(interface);
        frame.direction = Some(Direction::Inbound);
        frame
    }

    fn arp_reply(request: &NeighborRequest, target_mac: MacAddress) -> Frame {
        let (IpAddr::V4(source), IpAddr::V4(target)) = (request.interface_source, request.target)
        else {
            panic!("IPv4 request required");
        };
        let mut frame = ethernet_prefix(
            request.interface_mac,
            target_mac,
            &request.vlan_tags,
            ETHERTYPE_ARP,
        );
        frame.extend_from_slice(&[0, 1, 0x08, 0, 6, 4, 0, 2]);
        frame.extend_from_slice(&target_mac.0);
        frame.extend_from_slice(&target.octets());
        frame.extend_from_slice(&request.interface_mac.0);
        frame.extend_from_slice(&source.octets());
        frame.resize(
            ETHERNET_MINIMUM_WITHOUT_FCS + request.vlan_tags.len() * VLAN_HEADER_LENGTH,
            0,
        );
        captured(Bytes::from(frame), request.interface.index)
    }

    fn neighbor_advertisement(request: &NeighborRequest, target_mac: MacAddress) -> Frame {
        let (IpAddr::V6(interface_source), IpAddr::V6(target)) =
            (request.interface_source, request.target)
        else {
            panic!("IPv6 request required");
        };
        let mut icmp = Vec::with_capacity(NEIGHBOR_SOLICITATION_LENGTH);
        icmp.extend_from_slice(&[NEIGHBOR_ADVERTISEMENT_TYPE, 0, 0, 0]);
        icmp.extend_from_slice(&(SOLICITED_ADVERTISEMENT_FLAG | (1 << 29)).to_be_bytes());
        icmp.extend_from_slice(&target.octets());
        icmp.extend_from_slice(&[TARGET_LINK_LAYER_OPTION, 1]);
        icmp.extend_from_slice(&target_mac.0);
        let checksum = icmpv6_checksum(target, interface_source, &icmp);
        icmp[2..4].copy_from_slice(&checksum.to_be_bytes());

        let mut frame = ethernet_prefix(
            request.interface_mac,
            target_mac,
            &request.vlan_tags,
            ETHERTYPE_IPV6,
        );
        frame.extend_from_slice(&[0x60, 0, 0, 0]);
        frame.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
        frame.extend_from_slice(&[IPV6_NEXT_HEADER_ICMP, 255]);
        frame.extend_from_slice(&target.octets());
        frame.extend_from_slice(&interface_source.octets());
        frame.extend_from_slice(&icmp);
        captured(Bytes::from(frame), request.interface.index)
    }

    #[test]
    fn arp_resolution_preserves_vlan_route_and_uses_cache() {
        let mut request = request("192.0.2.7", "192.0.2.1");
        request.vlan_tags = vec![
            NeighborVlanTag {
                kind: NeighborVlanKind::Ieee8021Ad,
                priority: 5,
                drop_eligible: false,
                vlan_id: 100,
            },
            NeighborVlanTag {
                kind: NeighborVlanKind::Ieee8021Q,
                priority: 1,
                drop_eligible: true,
                vlan_id: 200,
            },
        ];
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| vec![arp_reply(&response_request, target_mac)]),
            options(),
        );

        let resolution = resolver.resolve_request(&request).unwrap();
        assert_eq!(resolution.mac_address, target_mac);
        assert_eq!(resolution.attempts, 1);
        assert_eq!(resolution.captured.len(), 1);
        assert!(!resolution.cache_hit);
        let state = shared.lock();
        assert_eq!(state.shutdowns, 1);
        assert_eq!(state.sent.len(), 1);
        assert_eq!(
            state.sent[0].len(),
            ETHERNET_MINIMUM_WITHOUT_FCS + 2 * VLAN_HEADER_LENGTH
        );
        assert_eq!(&state.sent[0][..6], &[0xff; 6]);
        assert_eq!(&state.sent[0][6..12], &request.interface_mac.0);
        assert_eq!(
            &state.sent[0][12..14],
            &ETHERTYPE_SERVICE_VLAN.to_be_bytes()
        );
        assert_eq!(state.planned[0].route.mtu, request.mtu);
        assert_eq!(state.planned[0].neighbor_vlan_tags, request.vlan_tags);
        drop(state);

        let cached = resolver.resolve_request(&request).unwrap();
        assert!(cached.cache_hit);
        assert_eq!(cached.attempts, 0);
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn arp_response_without_ingress_time_is_evidence_only() {
        let request = request("192.0.2.7", "192.0.2.1");
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let mut bounded = options();
        bounded.max_attempts = 1;
        bounded.attempt_timeout = Duration::from_millis(5);
        let resolver = resolver_without_ingress_time(
            Arc::clone(&shared),
            Arc::new(move |_| vec![arp_reply(&response_request, target_mac)]),
            bounded,
        );

        let error = resolver.resolve_request(&request).unwrap_err();

        assert!(matches!(
            error,
            NeighborError::NotFound {
                attempts: 1,
                captured,
                ..
            } if captured.len() == 1
        ));
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn ndp_solicitation_and_advertisement_follow_wire_contract() {
        let request = request("2001:db8::7", "2001:db8::1");
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| vec![neighbor_advertisement(&response_request, target_mac)]),
            options(),
        );

        let resolution = resolver.resolve_request(&request).unwrap();
        assert_eq!(resolution.mac_address, target_mac);
        let sent = shared.lock().sent[0].clone();
        assert_eq!(&sent[..6], &[0x33, 0x33, 0xff, 0, 0, 1]);
        assert_eq!(sent[20], IPV6_NEXT_HEADER_ICMP);
        assert_eq!(sent[21], 255);
        let destination = ipv6_address(&sent[38..54]);
        assert_eq!(destination, "ff02::1:ff00:1".parse::<Ipv6Addr>().unwrap());
        let icmp = &sent[ETHERNET_HEADER_LENGTH + IPV6_HEADER_LENGTH..];
        assert_eq!(icmp[0], NEIGHBOR_SOLICITATION_TYPE);
        assert_eq!(
            &icmp[8..24],
            &request
                .target
                .to_string()
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
        );
        assert_eq!(&icmp[24..26], &[SOURCE_LINK_LAYER_OPTION, 1]);
        assert_eq!(
            icmpv6_checksum(
                request.interface_source.to_string().parse().unwrap(),
                destination,
                icmp
            ),
            0
        );
    }

    #[test]
    fn ndp_rejects_bad_checksum_before_accepting_correlated_evidence() {
        let request = request("2001:db8::7", "2001:db8::1");
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| {
                let valid = neighbor_advertisement(&response_request, target_mac);
                let mut bad = valid.clone();
                let mut bytes = bad.bytes.to_vec();
                bytes[ETHERNET_HEADER_LENGTH + IPV6_HEADER_LENGTH + 2] ^= 0xff;
                bad.bytes = Bytes::from(bytes);
                vec![bad, valid]
            }),
            options(),
        );

        let resolution = resolver.resolve_request(&request).unwrap();
        assert_eq!(resolution.mac_address, target_mac);
        assert_eq!(resolution.attempts, 1);
        assert_eq!(resolution.captured.len(), 2);
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn arp_rejects_responses_from_another_vlan_or_interface() {
        let mut request = request("192.0.2.7", "192.0.2.1");
        request.vlan_tags.push(NeighborVlanTag {
            kind: NeighborVlanKind::Ieee8021Q,
            priority: 0,
            drop_eligible: false,
            vlan_id: 100,
        });
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let correct_request = request.clone();
        let mut other_vlan_request = request.clone();
        other_vlan_request.vlan_tags[0].vlan_id = 101;
        let shared = Arc::new(MockShared::default());
        let mut bounded = options();
        bounded.max_attempts = 1;
        bounded.attempt_timeout = Duration::from_millis(5);
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| {
                let wrong_vlan = arp_reply(&other_vlan_request, target_mac);
                let mut wrong_interface = arp_reply(&correct_request, target_mac);
                wrong_interface.interface = Some(correct_request.interface.index + 1);
                vec![wrong_vlan, wrong_interface]
            }),
            bounded,
        );

        let error = resolver.resolve_request(&request).unwrap_err();
        assert!(matches!(
            error,
            NeighborError::NotFound {
                attempts: 1,
                captured,
                ..
            } if captured.len() == 2
        ));
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn timeout_is_bounded_attempted_and_joined() {
        let request = request("192.0.2.7", "192.0.2.99");
        let shared = Arc::new(MockShared::default());
        let mut bounded = options();
        bounded.max_capture_queue_frames = 1;
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(|_| {
                vec![captured(
                    Bytes::from_static(&[0; ETHERNET_HEADER_LENGTH]),
                    7,
                )]
            }),
            bounded,
        );
        let error = resolver.resolve_request(&request).unwrap_err();
        assert_eq!(
            error.classification().category,
            crate::error::Category::Timeout
        );
        let NeighborError::NotFound {
            attempts,
            captured,
            evidence_truncated,
            ..
        } = error
        else {
            panic!("unexpected error: {error}");
        };
        assert_eq!(attempts, 2);
        assert_eq!(captured.len(), 1);
        assert!(evidence_truncated);
        let state = shared.lock();
        assert_eq!(state.sent.len(), 2);
        assert_eq!(state.shutdowns, 1);
    }

    #[test]
    fn pre_request_frames_cannot_satisfy_lookup_and_evidence_is_bounded() {
        let request = request("192.0.2.7", "192.0.2.1");
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let shared = Arc::new(MockShared::default());
        shared
            .lock()
            .frames
            .push_back(CapturedFrame::new(
                arp_reply(&request, target_mac),
                Instant::now(),
            ));
        let response_request = request.clone();
        let mut bounded = options();
        bounded.max_capture_queue_frames = 1;
        let resolver = resolver(
            Arc::clone(&shared),
            Arc::new(move |_| {
                let mut response = arp_reply(&response_request, target_mac);
                response.timestamp = UNIX_EPOCH + Duration::from_secs(1);
                vec![response]
            }),
            bounded,
        );
        let resolution = resolver.resolve_request(&request).unwrap();
        assert_eq!(resolution.mac_address, target_mac);
        assert_eq!(resolution.captured.len(), 1);
        assert_eq!(
            resolution.captured[0].timestamp,
            UNIX_EPOCH + Duration::from_secs(1)
        );
        assert!(resolution.evidence_truncated);
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn matching_frame_in_drain_to_send_race_is_evidence_only() {
        let request = request("192.0.2.7", "192.0.2.1");
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let mut bounded = options();
        bounded.max_attempts = 1;
        let resolver = resolver_with_pre_send_responses(
            Arc::clone(&shared),
            Arc::new(move |_| {
                vec![
                    arp_reply(&response_request, target_mac),
                    arp_reply(&response_request, target_mac),
                ]
            }),
            1,
            bounded,
        );

        let resolution = resolver.resolve_request(&request).unwrap();
        assert_eq!(resolution.mac_address, target_mac);
        assert_eq!(resolution.attempts, 1);
        assert_eq!(resolution.captured.len(), 2);
        assert_eq!(shared.lock().sent.len(), 1);
    }

    #[test]
    fn low_mtu_rejects_ndp_before_native_side_effects() {
        let mut request = request("2001:db8::7", "2001:db8::1");
        request.mtu = 64;
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(Arc::clone(&shared), Arc::new(|_| Vec::new()), options());
        assert!(matches!(
            resolver.resolve_request(&request),
            Err(NeighborError::InvalidRequest { .. })
        ));
        let state = shared.lock();
        assert!(state.sent.is_empty());
        assert!(state.planned.is_empty());
    }

    #[test]
    fn low_mtu_rejects_arp_before_native_side_effects() {
        let mut request = request("192.0.2.7", "192.0.2.1");
        request.mtu = (ARP_PAYLOAD_LENGTH - 1) as u32;
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(Arc::clone(&shared), Arc::new(|_| Vec::new()), options());
        assert!(matches!(
            resolver.resolve_request(&request),
            Err(NeighborError::InvalidRequest { .. })
        ));
        let state = shared.lock();
        assert!(state.sent.is_empty());
        assert!(state.planned.is_empty());
    }

    #[test]
    fn invalid_options_fail_before_provider_construction() {
        let mut invalid = options();
        invalid.max_attempts = 0;
        assert!(matches!(
            invalid.validate(),
            Err(NeighborError::InvalidConfiguration { .. })
        ));
        let mut invalid = options();
        invalid.snap_length = 64;
        assert!(matches!(
            invalid.validate(),
            Err(NeighborError::InvalidConfiguration { .. })
        ));
    }

    #[test]
    fn direct_resolve_uses_interface_owned_metadata() {
        let target_mac = MacAddress([0x02, 0, 0, 0, 0, 1]);
        let request = request("192.0.2.7", "192.0.2.1");
        let response_request = request.clone();
        let shared = Arc::new(MockShared::default());
        let resolver = resolver(
            shared,
            Arc::new(move |_| vec![arp_reply(&response_request, target_mac)]),
            options(),
        );
        assert_eq!(
            resolver
                .resolve(&request.interface, request.interface_source, request.target)
                .unwrap(),
            target_mac
        );
    }

    #[test]
    fn checksum_carries_across_odd_part_boundaries() {
        assert_eq!(checksum(&[&[0x12], &[0x34, 0x56], &[0x78]]), 0x9753);
    }

    #[test]
    fn captured_helper_uses_stable_timestamp() {
        let frame = captured(Bytes::from_static(&[0; 14]), 7);
        assert_eq!(frame.timestamp, SystemTime::UNIX_EPOCH);
    }
}
