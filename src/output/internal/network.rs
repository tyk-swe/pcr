/// Stable interface shape used by both the text and JSON renderers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct InterfaceFlagsOutput {
    pub up: bool,
    pub broadcast: bool,
    pub loopback: bool,
    pub point_to_point: bool,
    pub multicast: bool,
}

impl From<InterfaceFlags> for InterfaceFlagsOutput {
    fn from(value: InterfaceFlags) -> Self {
        Self {
            up: value.up,
            broadcast: value.broadcast,
            loopback: value.loopback,
            point_to_point: value.point_to_point,
            multicast: value.multicast,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceCapabilityOutput {
    Layer2,
    Layer3,
    Layer2And3,
}

impl From<LinkCapability> for InterfaceCapabilityOutput {
    fn from(value: LinkCapability) -> Self {
        match value {
            LinkCapability::Layer2 => Self::Layer2,
            LinkCapability::Layer3 => Self::Layer3,
            LinkCapability::Layer2And3 => Self::Layer2And3,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfaceOutput {
    pub name: String,
    pub index: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
    pub addresses: Vec<String>,
    pub flags: InterfaceFlagsOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u32>,
    pub capability: InterfaceCapabilityOutput,
    pub link_type: u32,
}

impl From<InterfaceInfo> for InterfaceOutput {
    fn from(interface: InterfaceInfo) -> Self {
        Self {
            name: interface.id.name,
            index: interface.id.index,
            description: interface.description,
            mac: interface.mac_address.map(|value| value.to_string()),
            addresses: interface
                .addresses
                .into_iter()
                .map(|value| format!("{}/{}", value.address, value.prefix_length))
                .collect(),
            flags: interface.flags.into(),
            mtu: interface.mtu,
            capability: interface.capability.into(),
            link_type: interface.link_type.0,
        }
    }
}

/// Aggregate result of `interfaces`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InterfacesCommandResult {
    pub interfaces: Vec<InterfaceOutput>,
}

impl InterfacesCommandResult {
    pub fn new(interfaces: Vec<InterfaceInfo>) -> Self {
        let mut interface_outputs = interfaces
            .into_iter()
            .map(InterfaceOutput::from)
            .collect::<Vec<_>>();
        for interface in &mut interface_outputs {
            interface.addresses.sort();
        }
        interface_outputs.sort_by(|left, right| {
            (left.index, left.name.as_str()).cmp(&(right.index, right.name.as_str()))
        });
        Self {
            interfaces: interface_outputs,
        }
    }
}

/// Aggregate result of `plan`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RouteInterfaceOutput {
    pub name: String,
    pub index: u32,
}

impl From<InterfaceId> for RouteInterfaceOutput {
    fn from(value: InterfaceId) -> Self {
        Self {
            name: value.name,
            index: value.index,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteSelectionOutput {
    Local,
    OnLink,
    Gateway,
    InterfaceOnly,
}

impl From<crate::net::route::SelectionReason> for RouteSelectionOutput {
    fn from(value: crate::net::route::SelectionReason) -> Self {
        match value {
            crate::net::route::SelectionReason::Local => Self::Local,
            crate::net::route::SelectionReason::OnLink => Self::OnLink,
            crate::net::route::SelectionReason::Gateway => Self::Gateway,
            crate::net::route::SelectionReason::InterfaceOnly => Self::InterfaceOnly,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteScopeOutput {
    Host,
    Link,
    Private,
    Global,
    Multicast,
    Unspecified,
}

impl From<crate::net::route::Scope> for RouteScopeOutput {
    fn from(value: crate::net::route::Scope) -> Self {
        match value {
            crate::net::route::Scope::Host => Self::Host,
            crate::net::route::Scope::Link => Self::Link,
            crate::net::route::Scope::Private => Self::Private,
            crate::net::route::Scope::Global => Self::Global,
            crate::net::route::Scope::Multicast => Self::Multicast,
            crate::net::route::Scope::Unspecified => Self::Unspecified,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteCapabilityOutput {
    Layer2,
    Layer3,
    Layer2And3,
}

impl From<LinkCapability> for RouteCapabilityOutput {
    fn from(value: LinkCapability) -> Self {
        match value {
            LinkCapability::Layer2 => Self::Layer2,
            LinkCapability::Layer3 => Self::Layer3,
            LinkCapability::Layer2And3 => Self::Layer2And3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteModeOutput {
    Auto,
    Layer2,
    Layer3,
}

impl From<LinkMode> for RouteModeOutput {
    fn from(value: LinkMode) -> Self {
        match value {
            LinkMode::Auto => Self::Auto,
            LinkMode::Layer2 => Self::Layer2,
            LinkMode::Layer3 => Self::Layer3,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RouteLinkTypeOutput(pub u32);

impl From<crate::capture::LinkType> for RouteLinkTypeOutput {
    fn from(value: crate::capture::LinkType) -> Self {
        Self(value.0)
    }
}

impl From<RouteLinkTypeOutput> for crate::capture::LinkType {
    fn from(value: RouteLinkTypeOutput) -> Self {
        Self(value.0)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RouteMacAddressOutput(pub [u8; 6]);

impl From<crate::net::link::MacAddress> for RouteMacAddressOutput {
    fn from(value: crate::net::link::MacAddress) -> Self {
        Self(value.0)
    }
}

impl fmt::Display for RouteMacAddressOutput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = self.0;
        write!(
            formatter,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            value[0], value[1], value[2], value[3], value[4], value[5]
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteVlanKindOutput {
    Ieee8021Q,
    Ieee8021Ad,
}

impl From<crate::net::neighbor::VlanKind> for RouteVlanKindOutput {
    fn from(value: crate::net::neighbor::VlanKind) -> Self {
        match value {
            crate::net::neighbor::VlanKind::Ieee8021Q => Self::Ieee8021Q,
            crate::net::neighbor::VlanKind::Ieee8021Ad => Self::Ieee8021Ad,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RouteVlanTagOutput {
    pub kind: RouteVlanKindOutput,
    pub priority: u8,
    pub drop_eligible: bool,
    pub vlan_id: u16,
}

impl From<crate::net::neighbor::VlanTag> for RouteVlanTagOutput {
    fn from(value: crate::net::neighbor::VlanTag) -> Self {
        Self {
            kind: value.kind.into(),
            priority: value.priority,
            drop_eligible: value.drop_eligible,
            vlan_id: value.vlan_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RouteDecisionOutput {
    pub interface: RouteInterfaceOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_mac: Option<RouteMacAddressOutput>,
    pub selected_address: Option<IpAddr>,
    pub preferred_source: Option<IpAddr>,
    pub next_hop: Option<IpAddr>,
    pub selection_reason: RouteSelectionOutput,
    pub destination_scope: RouteScopeOutput,
    pub mtu: u32,
    pub capability: RouteCapabilityOutput,
    pub link_type: RouteLinkTypeOutput,
}

impl From<RouteDecision> for RouteDecisionOutput {
    fn from(value: RouteDecision) -> Self {
        Self {
            interface: value.interface.into(),
            source_mac: value.source_mac.map(Into::into),
            selected_address: value.selected_address,
            preferred_source: value.preferred_source,
            next_hop: value.next_hop,
            selection_reason: value.selection_reason.into(),
            destination_scope: value.destination_scope.into(),
            mtu: value.mtu,
            capability: value.capability.into(),
            link_type: value.link_type.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlannedRouteOutput {
    pub route: RouteDecisionOutput,
    pub mode: RouteModeOutput,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lookup_destination: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_destination: Option<IpAddr>,
    pub visited_destinations: Vec<IpAddr>,
    pub packet_source: Option<IpAddr>,
    pub neighbor_source: Option<IpAddr>,
    pub neighbor_target: Option<IpAddr>,
    pub destination_mac: Option<RouteMacAddressOutput>,
    pub source_mac: Option<RouteMacAddressOutput>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub neighbor_vlan_tags: Vec<RouteVlanTagOutput>,
    pub synthesized_ethernet: bool,
}

impl From<PlannedRoute> for PlannedRouteOutput {
    fn from(value: PlannedRoute) -> Self {
        Self {
            route: value.route.into(),
            mode: value.mode.into(),
            lookup_destination: value.lookup_destination,
            final_destination: value.final_destination,
            visited_destinations: value.visited_destinations,
            packet_source: value.packet_source,
            neighbor_source: value.neighbor_source,
            neighbor_target: value.neighbor_target,
            destination_mac: value.destination_mac.map(Into::into),
            source_mac: value.source_mac.map(Into::into),
            neighbor_vlan_tags: value
                .neighbor_vlan_tags
                .into_iter()
                .map(Into::into)
                .collect(),
            synthesized_ethernet: value.synthesized_ethernet,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanCommandResult {
    pub route: PlannedRouteOutput,
}

/// Aggregate result of `routes`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RoutesCommandResult {
    pub routes: Vec<RouteDecisionOutput>,
}

/// Serializable route materialization evidence retained by send-like commands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MaterializedRouteOutput {
    pub plan: PlannedRouteOutput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub neighbor: Option<NeighborEvidenceOutput>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NeighborEvidenceOutput {
    pub mac_address: String,
    pub attempts: u32,
    pub cache_hit: bool,
    pub captured: Vec<FrameOutput>,
    pub evidence_truncated: bool,
    pub capture_statistics: CaptureStats,
}

impl MaterializedRouteOutput {
    pub fn try_from_route(route: MaterializedRoute) -> Result<Self, OutputContractError> {
        let neighbor = route
            .neighbor_resolution
            .map(|resolution| {
                let captured = resolution
                    .captured
                    .into_iter()
                    .map(FrameOutput::try_from_frame)
                    .collect::<Result<Vec<_>, _>>()?;
                Ok(NeighborEvidenceOutput {
                    mac_address: resolution.mac_address.to_string(),
                    attempts: resolution.attempts,
                    cache_hit: resolution.cache_hit,
                    captured,
                    evidence_truncated: resolution.evidence_truncated,
                    capture_statistics: resolution.capture_statistics.into(),
                })
            })
            .transpose()?;
        Ok(Self {
            plan: route.plan.into(),
            neighbor,
        })
    }
}

/// Aggregate result of `send`; operation statistics live in the envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SendCommandResult {
    pub frame: WireFrameOutput,
    pub route: MaterializedRouteOutput,
}

impl SendCommandResult {
    pub fn try_from_report(
        report: SendReport,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let SendReport {
            built,
            route,
            wire_bytes,
            stats,
        } = report;
        let frame = WireFrameOutput::new(wire_bytes.unwrap_or_else(|| built.bytes.clone()));
        Ok((
            Self {
                frame,
                route: MaterializedRouteOutput::try_from_route(route)?,
            },
            built.diagnostics,
            stats.into(),
        ))
    }
}

/// A decoded frame retained by exchange-like tools.
#[derive(Clone, Debug, Serialize)]
pub struct DecodedFrameOutput {
    pub frame: FrameOutput,
    pub packet: PacketDocument,
    pub layout: PacketLayout,
    pub diagnostics: Vec<DiagnosticOutput>,
}

impl DecodedFrameOutput {
    pub fn try_from_decoded(decoded: DecodedPacket) -> Result<Self, OutputContractError> {
        let DecodedPacket {
            packet,
            original: _,
            frame,
            layout,
            diagnostics,
        } = decoded;
        Ok(Self {
            frame: FrameOutput::try_from_frame(frame)?,
            packet: PacketDocument::from_packet(&packet),
            layout,
            diagnostics: diagnostics.into_iter().map(Into::into).collect(),
        })
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ExchangeResponseOutput {
    #[serde(serialize_with = "serialize_u64_decimal")]
    pub request_index: u64,
    pub response: DecodedFrameOutput,
    #[serde(serialize_with = "serialize_duration")]
    pub latency: Duration,
}

/// Aggregate result of `exchange`; diagnostics and statistics live in the envelope.
#[derive(Clone, Debug, Serialize)]
pub struct ExchangeCommandResult {
    pub sent: Vec<WireFrameOutput>,
    pub responses: Vec<ExchangeResponseOutput>,
    #[serde(serialize_with = "serialize_u64_vec_decimal")]
    pub unanswered: Vec<u64>,
    pub unsolicited: Vec<DecodedFrameOutput>,
    pub undecoded: Vec<FrameOutput>,
}

impl ExchangeCommandResult {
    pub fn try_from_exchange(
        result: ExchangeResult,
    ) -> Result<(Self, Vec<Diagnostic>, OperationStats), OutputContractError> {
        let ExchangeResult {
            sent,
            sent_evidence: _,
            responses,
            unanswered,
            unsolicited,
            undecoded,
            mut diagnostics,
            stats,
        } = result;
        let sent_frames = sent
            .into_iter()
            .map(|built| {
                diagnostics.extend(built.diagnostics);
                WireFrameOutput::new(built.bytes)
            })
            .collect();
        let response_outputs = responses
            .into_iter()
            .map(|response| {
                Ok(ExchangeResponseOutput {
                    request_index: response.request_index as u64,
                    response: DecodedFrameOutput::try_from_decoded(response.response)?,
                    latency: response.latency,
                })
            })
            .collect::<Result<Vec<_>, OutputContractError>>()?;
        let unsolicited_outputs = unsolicited
            .into_iter()
            .map(DecodedFrameOutput::try_from_decoded)
            .collect::<Result<Vec<_>, _>>()?;
        let undecoded_frames = undecoded
            .into_iter()
            .map(FrameOutput::try_from_frame)
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            Self {
                sent: sent_frames,
                responses: response_outputs,
                unanswered: unanswered.into_iter().map(|index| index as u64).collect(),
                unsolicited: unsolicited_outputs,
                undecoded: undecoded_frames,
            },
            diagnostics,
            stats.into(),
        ))
    }
}

/// One NDJSON event produced by `exchange`.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ExchangeStreamCommandResult {
    Sent {
        #[serde(serialize_with = "serialize_u64_decimal")]
        request_index: u64,
        frame: WireFrameOutput,
    },
    Response {
        #[serde(serialize_with = "serialize_u64_decimal")]
        request_index: u64,
        response: DecodedFrameOutput,
        #[serde(serialize_with = "serialize_duration")]
        latency: Duration,
    },
    Unanswered {
        #[serde(serialize_with = "serialize_u64_decimal")]
        request_index: u64,
    },
    Unsolicited {
        frame: DecodedFrameOutput,
    },
    Undecoded {
        frame: FrameOutput,
    },
    Complete {
        #[serde(serialize_with = "serialize_u64_vec_decimal")]
        unanswered: Vec<u64>,
    },
}
