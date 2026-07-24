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

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
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

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
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

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
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

    fn lookup(
        &self,
        destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
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
    static FIELDS: &[FieldSchema] = &[];
    SCHEMA.get_or_init(|| LayerSchema {
        protocol: ProtocolId::new("test.mac_sensitive"),
        name: "MAC-sensitive test layer",
        fields: FIELDS,
    })
}

impl Layer for MacSensitiveLayer {
    fn schema(&self) -> &'static LayerSchema {
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

    fn field(&self, _name: &str) -> Option<FieldValue> {
        None
    }

    fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownField {
            protocol: self.protocol_id(),
            field: name.to_owned(),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CustomRouteLayer;

impl Layer for CustomRouteLayer {
    fn schema(&self) -> &'static LayerSchema {
        static SCHEMA: OnceLock<LayerSchema> = OnceLock::new();
        static FIELDS: &[FieldSchema] = &[FieldSchema {
            name: "destination",
            kind: FieldKind::Ipv4,
            derived: false,
            required: true,
            description: "custom route-bearing destination",
        }];
        SCHEMA.get_or_init(|| LayerSchema {
            protocol: ProtocolId::new("test.custom_route"),
            name: "Custom route-bearing test layer",
            fields: FIELDS,
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

    fn field(&self, _name: &str) -> Option<FieldValue> {
        None
    }

    fn set_field(&mut self, name: &str, _value: FieldValue) -> Result<(), FieldError> {
        Err(FieldError::UnknownField {
            protocol: self.protocol_id(),
            field: name.to_owned(),
        })
    }
}

#[derive(Debug)]
pub(crate) struct MacSensitiveCodec;

impl LayerCodec for MacSensitiveCodec {
    fn protocol_id(&self) -> ProtocolId {
        ProtocolId::new("test.mac_sensitive")
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
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
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayerValue, CodecError> {
        if input.is_empty() {
            return Err(CodecError::Truncated {
                protocol: self.protocol_id(),
                needed: 1,
                available: 0,
            });
        }
        Ok(DecodedLayerValue::terminal(Box::new(MacSensitiveLayer), 1))
    }

    fn make_layer(
        &self,
        _fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, CodecError> {
        Ok(Box::new(MacSensitiveLayer))
    }
}

#[derive(Debug)]
pub(crate) struct SlowMatcher(pub(crate) Duration);

impl Matcher for SlowMatcher {
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

    fn lookup(
        &self,
        _destination: IpAddr,
        _interface_hint: Option<&InterfaceId>,
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
    fn resolve(
        &self,
        _interface: &InterfaceId,
        _interface_source: IpAddr,
        _target: IpAddr,
    ) -> Result<MacAddress, NeighborError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(MacAddress([0, 1, 2, 3, 4, 5]))
    }
}

#[derive(Clone, Copy)]
pub(crate) struct FailingNeighbors;

impl NeighborResolver for FailingNeighbors {
    fn resolve(
        &self,
        interface: &InterfaceId,
        _interface_source: IpAddr,
        target: IpAddr,
    ) -> Result<MacAddress, NeighborError> {
        Err(NeighborError::Resolution {
            interface: interface.name.clone(),
            target,
            message: "deterministic test failure".to_owned(),
        })
    }
}
