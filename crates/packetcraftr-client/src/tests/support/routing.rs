// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::super::*;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct RejectingPacketIo;

impl PacketIo for RejectingPacketIo {
    fn send(&self, _frame: TransmissionFrame<'_>) -> Result<IoSendReport, LiveIoError> {
        Err(LiveIoError::Unsupported {
            message: "test backend does not support live I/O".to_owned(),
        })
    }
}

pub(crate) struct FixedRoutes(pub(crate) RouteDecision);

impl RouteProvider for FixedRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        Ok(self.0.clone())
    }
}

#[derive(Clone)]
pub(crate) struct CountingRoutes {
    pub(crate) decision: RouteDecision,
    pub(crate) calls: Arc<AtomicUsize>,
}

impl RouteProvider for CountingRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(self.decision.clone())
    }
}
pub(crate) struct SlowRoutes {
    pub(crate) decision: RouteDecision,
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) delay: Duration,
}

impl RouteProvider for SlowRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(self.delay);
        Ok(self.decision.clone())
    }
}

#[derive(Clone)]
pub(crate) struct DestinationRoutes {
    pub(crate) calls: Arc<AtomicUsize>,
}

impl RouteProvider for DestinationRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut decision = route(LinkCapability::Layer3);
        if destination == IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)) {
            decision.interface = InterfaceId {
                name: "other0".to_owned(),
                index: 8,
            };
        }
        Ok(decision)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MacSensitiveLayer;

pub(crate) fn mac_sensitive_schema() -> &'static LayerSchema {
    static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
    SCHEMA.get_or_init(|| {
        LayerSchema::empty(
            ProtocolId::from_static("test.mac_sensitive"),
            "MAC-sensitive test layer",
            std::iter::empty::<&str>(),
        )
        .unwrap()
    })
}

impl Layer for MacSensitiveLayer {
    fn schema(&self) -> &LayerSchema {
        mac_sensitive_schema()
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field_by_id(&self, _id: &FieldId) -> Option<FieldValue> {
        None
    }

    fn set_field_by_id(&mut self, id: &FieldId, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownFieldId {
            protocol: self.protocol_id().clone(),
            field: id.clone(),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CustomRouteLayer;

impl Layer for CustomRouteLayer {
    fn schema(&self) -> &LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        SCHEMA.get_or_init(|| {
            LayerSchema::new(
                ProtocolId::from_static("test.custom_route"),
                "Custom route-bearing test layer",
                std::iter::empty::<&str>(),
                1,
                [FieldSchema::new(
                    FieldId::from_static("destination"),
                    "destination",
                    std::iter::empty::<&str>(),
                    FieldKind::Ipv4,
                    true,
                    false,
                    "custom route-bearing destination",
                    FieldConstraints::default(),
                )
                .unwrap()],
            )
            .unwrap()
        })
    }

    fn clone_box(&self) -> Box<dyn Layer> {
        Box::new(self.clone())
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }

    fn field_by_id(&self, _id: &FieldId) -> Option<FieldValue> {
        None
    }

    fn set_field_by_id(&mut self, id: &FieldId, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownFieldId {
            protocol: self.protocol_id().clone(),
            field: id.clone(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct MacSensitiveCodec;

impl NativeLayerCodec for MacSensitiveCodec {
    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &NativeLayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, CodecError> {
        let source = context
            .packet
            .get::<Ethernet>()
            .expect("test packet has Ethernet")
            .source;
        Ok(EncodedLayer::header(vec![source[0]], layer.clone_box()))
    }

    fn decode(
        &self,
        input: &[u8],
        _context: &NativeLayerDecodeContext,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.is_empty() {
            return Err(CodecError::Truncated {
                protocol: ProtocolId::from_static("test.mac_sensitive"),
                needed: 1,
                available: 0,
            });
        }
        Ok(DecodedLayerValue::terminal(Box::new(MacSensitiveLayer), 1))
    }

    fn make_layer(&self, _fields: &ValidatedFieldSet) -> Result<Box<dyn Layer>, CodecError> {
        Ok(Box::new(MacSensitiveLayer))
    }
}

pub(crate) fn catalog_with_mac_sensitive(
    matcher_delay: Option<Duration>,
) -> Arc<ProtocolCatalogSnapshot> {
    let provider_id = ProviderId::from_static("test.client.protocols");
    let origin = RegistrationOrigin::Native {
        provider: provider_id.clone(),
    };
    let key = ProviderProtocolKey::from_static("mac_sensitive");
    let implementation = NativeProtocolImplementation::new(key.clone(), MacSensitiveCodec);
    let implementation = match matcher_delay {
        Some(delay) => implementation.with_matcher(SlowMatcher(delay)),
        None => implementation,
    };
    let provider =
        NativeProtocolProvider::new(provider_id.clone(), origin.clone(), [implementation]).unwrap();
    let mut registrations = ProtocolRegistrationSet::new();
    registrations
        .register_provider(Arc::new(provider))
        .register_protocol(
            ProtocolRegistration::new(
                Arc::new(mac_sensitive_schema().clone()),
                provider_id,
                key,
                origin.clone(),
            )
            .with_matcher(matcher_delay.is_some()),
        )
        .binding(ProtocolBindingRegistration::canonical(
            ProtocolId::from_static("ethernet"),
            0x88b5,
            ProtocolId::from_static("test.mac_sensitive"),
            origin,
        ));

    let mut builder = ProtocolCatalogSnapshot::builder();
    builder.native_module(&BuiltinProtocols).unwrap();
    builder.registration_set(registrations);
    Arc::new(builder.build().unwrap())
}

#[derive(Debug)]
pub(crate) struct SlowMatcher(pub(crate) Duration);

impl NativeResponseMatcher for SlowMatcher {
    fn matches(&self, _request: &Packet, _response: &Packet) -> MatchResult {
        std::thread::sleep(self.0);
        MatchResult::matched(200, "slow test matcher")
    }
}

#[derive(Clone)]
pub(crate) struct RecordingHostnameResolver {
    pub(crate) calls: Arc<AtomicUsize>,
    pub(crate) results: Arc<Mutex<VecDeque<Vec<IpAddr>>>>,
}

impl HostnameResolver for RecordingHostnameResolver {
    fn resolve(
        &self,
        hostname: &Hostname,
        limit: usize,
    ) -> Result<Vec<IpAddr>, TargetResolutionError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let addresses = self.results.lock().unwrap().pop_front().unwrap_or_default();
        if addresses.len() > limit {
            return Err(TargetResolutionError::AddressLimit {
                hostname: hostname.to_string(),
                limit,
            });
        }
        Ok(addresses)
    }
}

#[derive(Clone)]
pub(crate) struct InterfaceRoutes {
    pub(crate) decision: RouteDecision,
    pub(crate) ip_lookups: Arc<AtomicUsize>,
    pub(crate) interface_lookups: Arc<AtomicUsize>,
}

impl RouteProvider for InterfaceRoutes {
    type Error = Infallible;

    fn lookup_with_preferences(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
        _preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        self.ip_lookups.fetch_add(1, Ordering::SeqCst);
        Ok(self.decision.clone())
    }

    fn lookup_interface(
        &self,
        _interface: &InterfaceId,
    ) -> Result<Option<RouteDecision>, Self::Error> {
        self.interface_lookups.fetch_add(1, Ordering::SeqCst);
        Ok(Some(self.decision.clone()))
    }
}

#[derive(Clone, Default)]
pub(crate) struct CountingNeighbors(pub(crate) Arc<AtomicUsize>);

impl NeighborResolver for CountingNeighbors {
    fn resolve_request(
        &self,
        _request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(NeighborResolution {
            mac_address: MacAddress([0, 1, 2, 3, 4, 5]),
            attempts: 1,
            cache_hit: false,
            captured: Vec::new(),
            evidence_truncated: false,
            capture_statistics: CaptureStatistics::default(),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FailingNeighbors;

impl NeighborResolver for FailingNeighbors {
    fn resolve_request(
        &self,
        request: &NeighborRequest,
    ) -> Result<NeighborResolution, NeighborError> {
        Err(NeighborError::Resolution {
            interface: request.interface.name.clone(),
            target: request.target,
            message: "deterministic test failure".to_owned(),
        })
    }
}
