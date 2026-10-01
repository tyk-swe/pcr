// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeMap;

use bytes::Bytes;

use crate::{
    codec::{DecodedLayer, EncodedLayer, LayerCodec, LayerDecodeContext, LayerEncodeContext},
    diagnostic::Diagnostic,
    field::FieldValue,
    layer::{Layer, reflective_layer},
    layout::FieldLayout,
};

use crate::protocol::common::{
    ensure_encode_budget, invalid, make_layer, protocol, strict_or_diagnostic, truncated,
    typed_layer,
};

use crate::protocol::BuiltinProtocol;

const NAME: &str = BuiltinProtocol::Stp.as_str();

const STP_HEADER_LEN: usize = 4;
const STP_CONFIG_LEN: usize = 35;
const STP_RST_LEN: usize = 36;

const BPDU_CONFIG: u8 = 0x00;
const BPDU_RST: u8 = 0x02;
const BPDU_TCN: u8 = 0x80;

const PRIORITY_MAX: u8 = 0xf;
const EXTENSION_MAX: u16 = 0xfff;
const PORT_ROLE_MAX: u8 = 3;

/// Spanning-tree BPDU (IEEE 802.1D / 802.1w): configuration, rapid
/// configuration, or topology change notification.
///
/// Fields a BPDU type does not carry (all but the 4-byte header for a TCN, the
/// trailing `version_1_length` for a configuration BPDU) keep their defaults
/// and are not written. Timer fields stay raw 1/256 s units.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stp {
    pub protocol_id: u16,
    pub version: u8,
    pub bpdu_type: u8,
    pub topology_change: bool,
    pub proposal: bool,
    pub port_role: u8,
    pub learning: bool,
    pub forwarding: bool,
    pub agreement: bool,
    pub topology_change_ack: bool,
    pub root_priority: u8,
    pub root_extension: u16,
    pub root_mac: [u8; 6],
    pub root_path_cost: u32,
    pub bridge_priority: u8,
    pub bridge_extension: u16,
    pub bridge_mac: [u8; 6],
    pub port_id: u16,
    pub message_age: u16,
    pub max_age: u16,
    pub hello_time: u16,
    pub forward_delay: u16,
    pub version_1_length: u8,
}

impl Default for Stp {
    fn default() -> Self {
        Self {
            protocol_id: 0,
            version: 0,
            bpdu_type: BPDU_CONFIG,
            topology_change: false,
            proposal: false,
            port_role: 0,
            learning: false,
            forwarding: false,
            agreement: false,
            topology_change_ack: false,
            root_priority: 8,
            root_extension: 0,
            root_mac: [0; 6],
            root_path_cost: 0,
            bridge_priority: 8,
            bridge_extension: 0,
            bridge_mac: [0; 6],
            port_id: 0x8001,
            message_age: 0,
            max_age: 20 * 256,
            hello_time: 2 * 256,
            forward_delay: 15 * 256,
            version_1_length: 0,
        }
    }
}

reflective_layer! {
    fn stp_schema() => { protocol: protocol(NAME), name: "STP" }
    impl Stp {
        "protocol_id" => { kind: Unsigned, derived: false, required: false, description: "Protocol identifier; the spanning tree protocol is 0", reflect: protocol_id, layout: (0, 2) },
        "version" => { kind: Unsigned, derived: false, required: false, description: "Protocol version: 0 for STP, 2 for RSTP", reflect: version, layout: (2, 3) },
        "bpdu_type" => { kind: Unsigned, derived: false, required: false, description: "BPDU type: 0x00 configuration, 0x02 rapid configuration, 0x80 topology change notification", reflect: bpdu_type, layout: (3, 4) },
        "topology_change" => { kind: Bool, derived: false, required: false, description: "Topology change flag", reflect: topology_change, layout: (4, 5) },
        "proposal" => { kind: Bool, derived: false, required: false, description: "RSTP proposal flag", reflect: proposal, layout: (4, 5) },
        "port_role" => { kind: Unsigned, derived: false, required: false, description: "2-bit RSTP port role: 0 unknown, 1 alternate or backup, 2 root, 3 designated", reflect_bounded: port_role, PORT_ROLE_MAX, layout: (4, 5) },
        "learning" => { kind: Bool, derived: false, required: false, description: "RSTP learning flag", reflect: learning, layout: (4, 5) },
        "forwarding" => { kind: Bool, derived: false, required: false, description: "RSTP forwarding flag", reflect: forwarding, layout: (4, 5) },
        "agreement" => { kind: Bool, derived: false, required: false, description: "RSTP agreement flag", reflect: agreement, layout: (4, 5) },
        "topology_change_ack" => { kind: Bool, derived: false, required: false, description: "Topology change acknowledgment flag", reflect: topology_change_ack, layout: (4, 5) },
        "root_priority" => { kind: Unsigned, derived: false, required: false, description: "4-bit root bridge priority in steps of 4096", reflect_bounded: root_priority, PRIORITY_MAX, layout: (5, 6) },
        "root_extension" => { kind: Unsigned, derived: false, required: false, description: "12-bit root bridge system ID extension", reflect_bounded: root_extension, EXTENSION_MAX, layout: (5, 7) },
        "root_mac" => { kind: Mac, derived: false, required: false, description: "Root bridge MAC address", reflect: root_mac, layout: (7, 13) },
        "root_path_cost" => { kind: Unsigned, derived: false, required: false, description: "Path cost to the root bridge", reflect: root_path_cost, layout: (13, 17) },
        "bridge_priority" => { kind: Unsigned, derived: false, required: false, description: "4-bit sending bridge priority in steps of 4096", reflect_bounded: bridge_priority, PRIORITY_MAX, layout: (17, 18) },
        "bridge_extension" => { kind: Unsigned, derived: false, required: false, description: "12-bit sending bridge system ID extension", reflect_bounded: bridge_extension, EXTENSION_MAX, layout: (17, 19) },
        "bridge_mac" => { kind: Mac, derived: false, required: false, description: "Sending bridge MAC address", reflect: bridge_mac, layout: (19, 25) },
        "port_id" => { kind: Unsigned, derived: false, required: false, description: "Sending port identifier", reflect: port_id, layout: (25, 27) },
        "message_age" => { kind: Unsigned, derived: false, required: false, description: "Message age in 1/256 second units", reflect: message_age, layout: (27, 29) },
        "max_age" => { kind: Unsigned, derived: false, required: false, description: "Maximum age in 1/256 second units", reflect: max_age, layout: (29, 31) },
        "hello_time" => { kind: Unsigned, derived: false, required: false, description: "Hello time in 1/256 second units", reflect: hello_time, layout: (31, 33) },
        "forward_delay" => { kind: Unsigned, derived: false, required: false, description: "Forward delay in 1/256 second units", reflect: forward_delay, layout: (33, 35) },
        "version_1_length" => { kind: Unsigned, derived: false, required: false, description: "RSTP version 1 length; always 0", reflect: version_1_length, layout: (35, 36) },
    }
    layout fn stp_full_layout();
}

/// Only the fields inside the `consumed` prefix exist on the wire.
fn stp_layout(consumed: usize) -> Vec<FieldLayout> {
    stp_full_layout()
        .into_iter()
        .filter(|field| field.range.end <= consumed)
        .collect()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BpduKind {
    Config,
    Rst,
    Tcn,
    Unknown,
}

impl BpduKind {
    fn of(bpdu_type: u8) -> Self {
        match bpdu_type {
            BPDU_CONFIG => Self::Config,
            BPDU_RST => Self::Rst,
            BPDU_TCN => Self::Tcn,
            _ => Self::Unknown,
        }
    }

    /// An unknown type has no defined body, so only its header is typed.
    fn wire_len(self) -> usize {
        match self {
            Self::Config => STP_CONFIG_LEN,
            Self::Rst => STP_RST_LEN,
            Self::Tcn | Self::Unknown => STP_HEADER_LEN,
        }
    }

    fn has_config_body(self) -> bool {
        matches!(self, Self::Config | Self::Rst)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Problem {
    ProtocolId,
    BpduType,
    Version,
    Reserved(&'static str),
    Version1Length,
}

impl Problem {
    fn decode_code(self) -> &'static str {
        match self {
            Self::ProtocolId => "decode.stp_protocol_id",
            Self::BpduType => "decode.stp_bpdu_type",
            Self::Version => "decode.stp_version",
            Self::Reserved(_) => "decode.stp_reserved",
            Self::Version1Length => "decode.stp_version_1_length",
        }
    }

    fn build_code(self) -> &'static str {
        match self {
            Self::ProtocolId => "build.stp_protocol_id",
            Self::BpduType => "build.stp_bpdu_type",
            Self::Version => "build.stp_version",
            Self::Reserved(_) => "build.stp_reserved",
            Self::Version1Length => "build.stp_version_1_length",
        }
    }

    fn field(self) -> &'static str {
        match self {
            Self::ProtocolId => "protocol_id",
            Self::BpduType => "bpdu_type",
            Self::Version => "version",
            Self::Reserved(field) => field,
            Self::Version1Length => "version_1_length",
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::ProtocolId => "the STP protocol identifier is defined only as 0",
            Self::BpduType => {
                "the BPDU type is not configuration (0x00), rapid configuration (0x02), or topology change notification (0x80)"
            }
            Self::Version => {
                "the protocol version disagrees with the BPDU type: configuration and topology change BPDUs carry version 0, rapid configuration BPDUs version 2 or later"
            }
            Self::Reserved(_) => {
                "flag bits other than topology change and its acknowledgment are reserved outside rapid configuration BPDUs"
            }
            Self::Version1Length => "the RSTP version 1 length must be 0",
        }
    }
}

/// Flag bits 1 to 6 exist only in rapid configuration BPDUs, so they are
/// reserved in every other type that carries flags.
fn reserved_flag(layer: &Stp, kind: BpduKind) -> Option<&'static str> {
    if kind != BpduKind::Config && !(kind == BpduKind::Rst && layer.version < 2) {
        return None;
    }
    if layer.proposal {
        Some("proposal")
    } else if layer.port_role != 0 {
        Some("port_role")
    } else if layer.learning {
        Some("learning")
    } else if layer.forwarding {
        Some("forwarding")
    } else if layer.agreement {
        Some("agreement")
    } else {
        None
    }
}

fn problems(layer: &Stp) -> Vec<Problem> {
    let kind = BpduKind::of(layer.bpdu_type);
    let mut problems = Vec::new();
    if layer.protocol_id != 0 {
        problems.push(Problem::ProtocolId);
    }
    let version_matches = match kind {
        BpduKind::Config | BpduKind::Tcn => layer.version == 0,
        BpduKind::Rst => layer.version >= 2,
        BpduKind::Unknown => {
            problems.push(Problem::BpduType);
            true
        }
    };
    if !version_matches {
        problems.push(Problem::Version);
    }
    if let Some(field) = reserved_flag(layer, kind) {
        problems.push(Problem::Reserved(field));
    }
    if kind == BpduKind::Rst && layer.version_1_length != 0 {
        problems.push(Problem::Version1Length);
    }
    problems
}

fn flags_byte(layer: &Stp) -> u8 {
    u8::from(layer.topology_change)
        | (u8::from(layer.proposal) << 1)
        | (layer.port_role << 2)
        | (u8::from(layer.learning) << 4)
        | (u8::from(layer.forwarding) << 5)
        | (u8::from(layer.agreement) << 6)
        | (u8::from(layer.topology_change_ack) << 7)
}

fn bridge_id_bytes(priority: u8, extension: u16, mac: [u8; 6]) -> [u8; 8] {
    let [extension_high, extension_low] = extension.to_be_bytes();
    let [m0, m1, m2, m3, m4, m5] = mac;
    [
        (priority << 4) | extension_high,
        extension_low,
        m0,
        m1,
        m2,
        m3,
        m4,
        m5,
    ]
}

fn split_bridge_id(id: [u8; 8]) -> (u8, u16, [u8; 6]) {
    let [high, low, m0, m1, m2, m3, m4, m5] = id;
    (
        high >> 4,
        u16::from_be_bytes([high & 0x0f, low]),
        [m0, m1, m2, m3, m4, m5],
    )
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct StpCodec;

impl LayerCodec for StpCodec {
    fn protocol_id(&self) -> &'static crate::layer::Id {
        &stp_schema().protocol
    }

    fn encode(
        &self,
        layer: &dyn Layer,
        _payload: &[u8],
        context: &LayerEncodeContext<'_>,
    ) -> Result<EncodedLayer, crate::codec::Error> {
        let layer = typed_layer::<Stp>(NAME, layer)?;
        let kind = BpduKind::of(layer.bpdu_type);
        ensure_encode_budget(NAME, kind.wire_len(), context)?;
        if layer.port_role > PORT_ROLE_MAX
            || layer.root_priority > PRIORITY_MAX
            || layer.bridge_priority > PRIORITY_MAX
            || layer.root_extension > EXTENSION_MAX
            || layer.bridge_extension > EXTENSION_MAX
        {
            return Err(invalid(NAME, "field exceeds its wire range"));
        }

        let mut diagnostics = Vec::new();
        for problem in problems(layer) {
            strict_or_diagnostic(
                NAME,
                problem.build_code(),
                problem.field(),
                problem.message(),
                context,
                &mut diagnostics,
            )?;
        }

        let mut prefix = Vec::with_capacity(kind.wire_len());
        prefix.extend_from_slice(&layer.protocol_id.to_be_bytes());
        prefix.push(layer.version);
        prefix.push(layer.bpdu_type);
        if kind.has_config_body() {
            prefix.push(flags_byte(layer));
            prefix.extend_from_slice(&bridge_id_bytes(
                layer.root_priority,
                layer.root_extension,
                layer.root_mac,
            ));
            prefix.extend_from_slice(&layer.root_path_cost.to_be_bytes());
            prefix.extend_from_slice(&bridge_id_bytes(
                layer.bridge_priority,
                layer.bridge_extension,
                layer.bridge_mac,
            ));
            prefix.extend_from_slice(&layer.port_id.to_be_bytes());
            for timer in [
                layer.message_age,
                layer.max_age,
                layer.hello_time,
                layer.forward_delay,
            ] {
                prefix.extend_from_slice(&timer.to_be_bytes());
            }
        }
        if kind == BpduKind::Rst {
            prefix.push(layer.version_1_length);
        }
        let fields = stp_layout(prefix.len());
        Ok(EncodedLayer::header(prefix, Box::new(layer.clone()))
            .with_fields(fields)
            .with_diagnostics(diagnostics))
    }

    fn decode(
        &self,
        input: Bytes,
        _context: &LayerDecodeContext<'_>,
    ) -> Result<DecodedLayer, crate::codec::Error> {
        let Some(header) = input.first_chunk::<STP_HEADER_LEN>() else {
            return Err(truncated(NAME, STP_HEADER_LEN, input.len()));
        };
        let mut layer = Stp {
            protocol_id: u16::from_be_bytes([header[0], header[1]]),
            version: header[2],
            bpdu_type: header[3],
            ..Stp::default()
        };
        let kind = BpduKind::of(layer.bpdu_type);
        if kind.has_config_body() {
            let Some(body) = input.first_chunk::<STP_CONFIG_LEN>() else {
                return Err(truncated(NAME, kind.wire_len(), input.len()));
            };
            let flags = body[4];
            layer.topology_change = flags & 0x01 != 0;
            layer.proposal = flags & 0x02 != 0;
            layer.port_role = (flags >> 2) & 0x03;
            layer.learning = flags & 0x10 != 0;
            layer.forwarding = flags & 0x20 != 0;
            layer.agreement = flags & 0x40 != 0;
            layer.topology_change_ack = flags & 0x80 != 0;
            (layer.root_priority, layer.root_extension, layer.root_mac) = split_bridge_id([
                body[5], body[6], body[7], body[8], body[9], body[10], body[11], body[12],
            ]);
            layer.root_path_cost = u32::from_be_bytes([body[13], body[14], body[15], body[16]]);
            (
                layer.bridge_priority,
                layer.bridge_extension,
                layer.bridge_mac,
            ) = split_bridge_id([
                body[17], body[18], body[19], body[20], body[21], body[22], body[23], body[24],
            ]);
            layer.port_id = u16::from_be_bytes([body[25], body[26]]);
            layer.message_age = u16::from_be_bytes([body[27], body[28]]);
            layer.max_age = u16::from_be_bytes([body[29], body[30]]);
            layer.hello_time = u16::from_be_bytes([body[31], body[32]]);
            layer.forward_delay = u16::from_be_bytes([body[33], body[34]]);
        }
        if kind == BpduKind::Rst {
            let Some(version_1_length) = input.get(STP_CONFIG_LEN).copied() else {
                return Err(truncated(NAME, STP_RST_LEN, input.len()));
            };
            layer.version_1_length = version_1_length;
        }

        let diagnostics = problems(&layer)
            .into_iter()
            .map(|problem| {
                Diagnostic::warning(problem.decode_code(), problem.message())
                    .at_field(problem.field())
            })
            .collect();
        let consumed = kind.wire_len();
        Ok(DecodedLayer {
            fields: stp_layout(consumed),
            layer: Box::new(layer),
            consumed,
            payload_len: 0,
            next: Vec::new(),
            diagnostics,
            stop: true,
            network: None,
        })
    }

    fn make_layer(
        &self,
        fields: &BTreeMap<String, FieldValue>,
    ) -> Result<Box<dyn Layer>, crate::codec::Error> {
        make_layer(Stp::default(), fields)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::Packet;

    fn encode(layer: &Stp, mode: crate::codec::Mode) -> Result<EncodedLayer, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry();
        let packet = Packet::new();
        let build_context = crate::codec::Context::default();
        let context = LayerEncodeContext {
            packet: &packet,
            index: 0,
            build_context: &build_context,
            mode,
            registry: &registry,
            child: None,
            remaining_packet_bytes: usize::MAX,
        };
        StpCodec.encode(layer, &[], &context)
    }

    fn decode(input: &[u8]) -> Result<DecodedLayer, crate::codec::Error> {
        let registry = crate::protocol::builtin::registry();
        let context = LayerDecodeContext {
            parent: None,
            registry: &registry,
            network: None,
            discriminator: None,
        };
        StpCodec.decode(Bytes::copy_from_slice(input), &context)
    }

    fn codes(diagnostics: &[Diagnostic]) -> Vec<&'static str> {
        diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code)
            .collect()
    }

    /// A configuration BPDU as sent by a root bridge with priority 32768.
    const CONFIG: [u8; 35] = [
        0x00, 0x00, 0x00, 0x00, 0x01, 0x80, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x81, 0x02, 0x00, 0x00, 0x00, 0x00, 0x02, 0x80, 0x80, 0x02, 0x00, 0x00, 0x14,
        0x00, 0x02, 0x00, 0x0f, 0x00,
    ];

    #[test]
    fn configuration_bpdu_has_typed_bridge_ids_and_an_exact_wire_image() {
        let decoded = decode(&CONFIG).unwrap();
        assert_eq!(decoded.consumed, 35);
        assert_eq!(decoded.payload_len, 0);
        assert!(decoded.stop);
        assert!(decoded.diagnostics.is_empty());
        let layer = decoded.layer.downcast_ref::<Stp>().unwrap().clone();
        assert!(layer.topology_change);
        assert_eq!(layer.root_priority, 8);
        assert_eq!(layer.root_extension, 2);
        assert_eq!(layer.root_mac, [0, 0, 0, 0, 1, 0]);
        assert_eq!(layer.root_path_cost, 4);
        assert_eq!(layer.bridge_priority, 8);
        assert_eq!(layer.bridge_extension, 0x102);
        assert_eq!(layer.bridge_mac, [0, 0, 0, 0, 2, 0x80]);
        assert_eq!(layer.port_id, 0x8002);
        assert_eq!(layer.forward_delay, 0x0f00);

        let encoded = encode(&layer, crate::codec::Mode::Strict).unwrap();
        assert_eq!(encoded.prefix, CONFIG);
        assert!(
            encoded
                .fields
                .iter()
                .all(|field| field.range.end <= CONFIG.len())
        );
    }

    #[test]
    fn tcn_and_rst_bpdus_round_trip_with_their_own_lengths() {
        let tcn = [0, 0, 0, 0x80];
        let decoded = decode(&tcn).unwrap();
        assert_eq!(decoded.consumed, 4);
        assert!(decoded.diagnostics.is_empty());
        let layer = decoded.layer.downcast_ref::<Stp>().unwrap();
        assert_eq!(
            encode(layer, crate::codec::Mode::Strict).unwrap().prefix,
            tcn
        );

        let mut rst = CONFIG.to_vec();
        rst[2] = 2;
        rst[3] = 2;
        rst[4] = 0x3c;
        rst.push(0);
        let decoded = decode(&rst).unwrap();
        assert_eq!(decoded.consumed, 36);
        assert!(decoded.diagnostics.is_empty());
        let layer = decoded.layer.downcast_ref::<Stp>().unwrap();
        assert_eq!(layer.port_role, 3);
        assert!(layer.learning && layer.forwarding && !layer.agreement);
        assert_eq!(
            encode(layer, crate::codec::Mode::Strict).unwrap().prefix,
            rst
        );
    }

    #[test]
    fn truncated_bodies_fail_without_reading_past_the_input() {
        for input in [&CONFIG[..3], &CONFIG[..34]] {
            assert!(matches!(
                decode(input),
                Err(crate::codec::Error::Truncated { .. })
            ));
        }
        let mut rst = CONFIG;
        rst[3] = 2;
        rst[2] = 2;
        assert!(matches!(
            decode(&rst),
            Err(crate::codec::Error::Truncated {
                needed: 36,
                available: 35,
                ..
            })
        ));
    }

    #[test]
    fn unknown_types_type_only_the_header_and_report_it() {
        let input = [0, 0, 0, 0x7f, 0xde, 0xad];
        let decoded = decode(&input).unwrap();
        assert_eq!(decoded.consumed, 4);
        assert_eq!(codes(&decoded.diagnostics), ["decode.stp_bpdu_type"]);
        let layer = decoded.layer.downcast_ref::<Stp>().unwrap();
        assert_eq!(
            encode(layer, crate::codec::Mode::Permissive)
                .unwrap()
                .prefix,
            input[..4]
        );
        assert!(encode(layer, crate::codec::Mode::Strict).is_err());
    }

    #[test]
    fn rst_with_version_zero_and_reserved_flags_is_reported_and_refused_when_strict() {
        let mut input = CONFIG.to_vec();
        input[3] = 2;
        input[4] = 0x02;
        input.push(0);
        let decoded = decode(&input).unwrap();
        assert_eq!(
            codes(&decoded.diagnostics),
            ["decode.stp_version", "decode.stp_reserved"]
        );
        let layer = decoded.layer.downcast_ref::<Stp>().unwrap();

        let encoded = encode(layer, crate::codec::Mode::Permissive).unwrap();
        assert_eq!(encoded.prefix, input);
        assert_eq!(
            codes(&encoded.diagnostics),
            ["build.stp_version", "build.stp_reserved"]
        );
        assert!(encode(layer, crate::codec::Mode::Strict).is_err());
    }

    #[test]
    fn nonzero_protocol_id_and_version_1_length_are_reported() {
        let mut input = CONFIG.to_vec();
        input[1] = 1;
        input[2] = 2;
        input[3] = 2;
        input.push(7);
        let decoded = decode(&input).unwrap();
        assert_eq!(
            codes(&decoded.diagnostics),
            ["decode.stp_protocol_id", "decode.stp_version_1_length"]
        );
        let layer = decoded.layer.downcast_ref::<Stp>().unwrap();
        let permissive = encode(layer, crate::codec::Mode::Permissive).unwrap();
        assert_eq!(permissive.prefix, input);
        assert_eq!(
            codes(&permissive.diagnostics),
            ["build.stp_protocol_id", "build.stp_version_1_length"]
        );
        assert!(encode(layer, crate::codec::Mode::Strict).is_err());

        for (protocol_id, version_1_length) in [(1, 0), (0, 7)] {
            let single = Stp {
                protocol_id,
                version: 2,
                bpdu_type: BPDU_RST,
                version_1_length,
                ..Stp::default()
            };
            assert!(
                encode(&single, crate::codec::Mode::Strict).is_err(),
                "{protocol_id} {version_1_length}"
            );
            let code = if protocol_id == 0 {
                "build.stp_version_1_length"
            } else {
                "build.stp_protocol_id"
            };
            assert_eq!(
                codes(
                    &encode(&single, crate::codec::Mode::Permissive)
                        .unwrap()
                        .diagnostics
                ),
                [code]
            );
        }
    }

    #[test]
    fn encoder_refuses_values_wider_than_their_wire_fields() {
        for layer in [
            Stp {
                port_role: 4,
                ..Stp::default()
            },
            Stp {
                root_priority: 16,
                ..Stp::default()
            },
            Stp {
                bridge_extension: 0x1000,
                ..Stp::default()
            },
        ] {
            let Err(error) = encode(&layer, crate::codec::Mode::Permissive) else {
                panic!("out-of-range STP layer unexpectedly encoded: {layer:?}");
            };
            assert!(error.to_string().contains("wire range"), "{error}");
        }
    }
}
