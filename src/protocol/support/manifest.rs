// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned public contract for built-in codecs, capture roots, and stable workflows.

use serde::Serialize;

use crate::packet::semantics::{BuiltinProtocol, builtin_protocol_catalog};

/// Schema identifier for the stable built-in protocol support manifest.
pub const PROTOCOL_SUPPORT_SCHEMA_V1: &str = "packetcraftr.protocol-support/v1";

/// One built-in codec row in the stable protocol contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolSupport {
    pub protocol: &'static str,
    pub aliases: &'static [&'static str],
    pub build: bool,
    pub dissect: bool,
    pub exact_round_trip: bool,
    pub matcher: bool,
    pub decode_only: bool,
}

/// Byte-order rule applied by a registered capture root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureRootByteOrder {
    /// A captured host-order field is detected and preserved as little or big endian.
    CapturedHost,
    /// Multi-byte header fields use network byte order.
    Network,
    /// The encapsulated protocol defines its own byte order.
    ProtocolDefined,
}

/// One numeric DLT/LINKTYPE binding in the default registry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CaptureRootSupport {
    pub link_type: u32,
    pub protocol: &'static str,
    pub byte_order: CaptureRootByteOrder,
    pub exact_round_trip: bool,
}

/// Packet-layer obligations for one stable CLI workflow.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct WorkflowProtocolSupport {
    pub workflow: &'static str,
    pub builds: &'static [&'static str],
    pub dissects: &'static [&'static str],
    pub matches: &'static [&'static str],
    pub capture_roots: bool,
    pub packet_independent: bool,
    pub notes: &'static str,
}

/// Strict fallback and preservation rules shared by all registry-driven workflows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolFallbackSupport {
    pub unknown_link_type_as_raw: bool,
    pub unknown_discriminator_as_raw: bool,
    pub strict_known_discriminator_requires_typed_codec: bool,
    pub malformed_bytes_preserved: bool,
}

/// Complete versioned built-in protocol contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolSupportManifest {
    pub schema: &'static str,
    pub protocols: &'static [ProtocolSupport],
    pub capture_roots: &'static [CaptureRootSupport],
    pub workflows: &'static [WorkflowProtocolSupport],
    pub fallback: ProtocolFallbackSupport,
}

pub(crate) fn aliases(protocol: &str) -> &'static [&'static str] {
    BuiltinProtocol::from_name(protocol)
        .map(BuiltinProtocol::aliases)
        .unwrap_or_else(|| panic!("missing built-in protocol support for {protocol}"))
}

macro_rules! define_protocol_support {
    ($(
        $variant:ident {
            canonical: $canonical:literal,
            aliases: [$($alias:literal),* $(,)?],
            constructible: $constructible:literal,
            dissect: $dissect:literal,
            exact_round_trip: $exact_round_trip:literal,
            matcher: $matcher:ident,
            codec: $codec:ident
        }
    )*) => {
        /// Every codec registered by [`crate::protocol::builtin::Module`], in
        /// stable manifest order.
        pub const BUILTIN_PROTOCOLS: &[ProtocolSupport] = &[$(
            ProtocolSupport {
                protocol: $canonical,
                aliases: &[$($alias),*],
                build: $constructible,
                dissect: $dissect,
                exact_round_trip: $exact_round_trip,
                matcher: define_protocol_support!(@matcher $matcher),
                decode_only: !$constructible,
            }
        ),*];
    };
    (@matcher none) => { false };
    (@matcher reverse_flow) => { true };
    (@matcher echo_v4) => { true };
    (@matcher echo_v6) => { true };
}

builtin_protocol_catalog!(define_protocol_support);

const fn capture_root(
    link_type: u32,
    protocol: BuiltinProtocol,
    byte_order: CaptureRootByteOrder,
) -> CaptureRootSupport {
    CaptureRootSupport {
        link_type,
        protocol: protocol.as_str(),
        byte_order,
        exact_round_trip: true,
    }
}

/// Every numeric capture root registered by the default built-in module.
///
/// Capture topology remains separate from identity metadata, but every edge is
/// typed so a protocol rename cannot silently leave a string binding behind.
pub const BUILTIN_CAPTURE_ROOTS: &[CaptureRootSupport] = &[
    capture_root(
        crate::capture::LinkType::NULL.0,
        BuiltinProtocol::BsdNull,
        CaptureRootByteOrder::CapturedHost,
    ),
    capture_root(
        crate::capture::LinkType::ETHERNET.0,
        BuiltinProtocol::Ethernet,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        crate::capture::LinkType::BSD_RAW.0,
        BuiltinProtocol::RawIp,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        crate::capture::LinkType::RAW.0,
        BuiltinProtocol::RawIp,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        crate::capture::LinkType::LOOP.0,
        BuiltinProtocol::BsdLoop,
        CaptureRootByteOrder::Network,
    ),
    capture_root(
        crate::capture::LinkType::LINUX_SLL.0,
        BuiltinProtocol::LinuxSll,
        CaptureRootByteOrder::Network,
    ),
    capture_root(
        crate::capture::LinkType::IPV4.0,
        BuiltinProtocol::Ipv4,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        crate::capture::LinkType::IPV6.0,
        BuiltinProtocol::Ipv6,
        CaptureRootByteOrder::ProtocolDefined,
    ),
    capture_root(
        crate::capture::LinkType::LINUX_SLL2.0,
        BuiltinProtocol::LinuxSll2,
        CaptureRootByteOrder::Network,
    ),
];

const NONE: &[&str] = &[];

const fn protocol_names<const N: usize>(protocols: [BuiltinProtocol; N]) -> [&'static str; N] {
    let mut names = [""; N];
    let mut index = 0;
    while index < N {
        names[index] = protocols[index].as_str();
        index += 1;
    }
    names
}

const DNS_MATCHER_VALUES: [&str; 2] = protocol_names([BuiltinProtocol::Tcp, BuiltinProtocol::Udp]);
const PROBE_MATCHER_VALUES: [&str; 4] = protocol_names([
    BuiltinProtocol::Icmpv4,
    BuiltinProtocol::Icmpv6,
    BuiltinProtocol::Tcp,
    BuiltinProtocol::Udp,
]);
const DNS_MATCHERS: &[&str] = &DNS_MATCHER_VALUES;
const PROBE_MATCHERS: &[&str] = &PROBE_MATCHER_VALUES;

#[derive(Clone, Copy)]
enum Capability {
    Build,
    Dissect,
    Matcher,
}

const fn supported_protocols<const N: usize>(capability: Capability) -> [&'static str; N] {
    let mut protocols = [""; N];
    let mut source = 0;
    let mut target = 0;
    while source < BuiltinProtocol::ALL.len() {
        let protocol = BuiltinProtocol::ALL[source];
        let supported = match capability {
            Capability::Build => protocol.is_constructible(),
            Capability::Dissect => protocol.is_dissectible(),
            Capability::Matcher => protocol.has_matcher(),
        };
        if supported {
            assert!(target < N, "too many protocols for capability list");
            protocols[target] = protocol.as_str();
            target += 1;
        }
        source += 1;
    }
    assert!(target == N, "too few protocols for capability list");
    protocols
}

const ALL_BUILD_VALUES: [&str; 24] = supported_protocols(Capability::Build);
const ALL_DISSECT_VALUES: [&str; 25] = supported_protocols(Capability::Dissect);
const MATCHER_VALUES: [&str; 5] = supported_protocols(Capability::Matcher);
const ALL_BUILD: &[&str] = &ALL_BUILD_VALUES;
const ALL_DISSECT: &[&str] = &ALL_DISSECT_VALUES;
const MATCHERS: &[&str] = &MATCHER_VALUES;
const LIVE_BUILD_VALUES: [&str; 20] = protocol_names([
    BuiltinProtocol::Arp,
    BuiltinProtocol::Ethernet,
    BuiltinProtocol::Gre,
    BuiltinProtocol::Icmpv4,
    BuiltinProtocol::Icmpv6,
    BuiltinProtocol::Igmp,
    BuiltinProtocol::Ipv4,
    BuiltinProtocol::Ipv6,
    BuiltinProtocol::Ipv6DestinationOptions,
    BuiltinProtocol::Ipv6Fragment,
    BuiltinProtocol::Ipv6HopByHop,
    BuiltinProtocol::Ipv6Srh,
    BuiltinProtocol::Malformed,
    BuiltinProtocol::Padding,
    BuiltinProtocol::Raw,
    BuiltinProtocol::Sctp,
    BuiltinProtocol::Tcp,
    BuiltinProtocol::Udp,
    BuiltinProtocol::Vlan,
    BuiltinProtocol::Vlan8021ad,
]);
const PROBE_BUILD_VALUES: [&str; 7] = protocol_names([
    BuiltinProtocol::Ethernet,
    BuiltinProtocol::Icmpv4,
    BuiltinProtocol::Icmpv6,
    BuiltinProtocol::Ipv4,
    BuiltinProtocol::Ipv6,
    BuiltinProtocol::Tcp,
    BuiltinProtocol::Udp,
]);
const DNS_BUILD_VALUES: [&str; 8] = protocol_names([
    BuiltinProtocol::Ethernet,
    BuiltinProtocol::Ipv4,
    BuiltinProtocol::Ipv6,
    BuiltinProtocol::Raw,
    BuiltinProtocol::Tcp,
    BuiltinProtocol::Udp,
    BuiltinProtocol::Vlan,
    BuiltinProtocol::Vlan8021ad,
]);
const DNS_DISSECT_VALUES: [&str; 9] = protocol_names([
    BuiltinProtocol::Ethernet,
    BuiltinProtocol::Ipv4,
    BuiltinProtocol::Ipv6,
    BuiltinProtocol::Malformed,
    BuiltinProtocol::Raw,
    BuiltinProtocol::Tcp,
    BuiltinProtocol::Udp,
    BuiltinProtocol::Vlan,
    BuiltinProtocol::Vlan8021ad,
]);
const LIVE_BUILD: &[&str] = &LIVE_BUILD_VALUES;
const PROBE_BUILD: &[&str] = &PROBE_BUILD_VALUES;
const DNS_BUILD: &[&str] = &DNS_BUILD_VALUES;
const DNS_DISSECT: &[&str] = &DNS_DISSECT_VALUES;

/// Packet-layer obligations for every command in the CLI surface.
pub const STABLE_WORKFLOW_PROTOCOLS: &[WorkflowProtocolSupport] = &[
    WorkflowProtocolSupport {
        workflow: "build",
        builds: ALL_BUILD,
        dissects: NONE,
        matches: NONE,
        capture_roots: false,
        packet_independent: false,
        notes: "offline construction accepts every constructible built-in codec",
    },
    WorkflowProtocolSupport {
        workflow: "dissect",
        builds: NONE,
        dissects: ALL_DISSECT,
        matches: NONE,
        capture_roots: true,
        packet_independent: false,
        notes: "bounded dissection starts from any registered or unknown numeric link type",
    },
    WorkflowProtocolSupport {
        workflow: "plan",
        builds: LIVE_BUILD,
        dissects: NONE,
        matches: NONE,
        capture_roots: false,
        packet_independent: false,
        notes: "capture-only link envelopes are rejected explicitly for live planning",
    },
    WorkflowProtocolSupport {
        workflow: "send",
        builds: LIVE_BUILD,
        dissects: NONE,
        matches: NONE,
        capture_roots: false,
        packet_independent: false,
        notes: "route materialization may add Ethernet, VLAN, ARP, or ICMPv6 neighbor traffic",
    },
    WorkflowProtocolSupport {
        workflow: "exchange",
        builds: LIVE_BUILD,
        dissects: ALL_DISSECT,
        matches: MATCHERS,
        capture_roots: true,
        packet_independent: false,
        notes: "capture is ready before send and typed matchers correlate supported responses",
    },
    WorkflowProtocolSupport {
        workflow: "capture",
        builds: LIVE_BUILD,
        dissects: NONE,
        matches: NONE,
        capture_roots: true,
        packet_independent: false,
        notes: "the route recipe is built while captured frames retain their open link types",
    },
    WorkflowProtocolSupport {
        workflow: "read",
        builds: NONE,
        dissects: NONE,
        matches: NONE,
        capture_roots: true,
        packet_independent: false,
        notes: "capture records are streamed without relabeling their link type or payload",
    },
    WorkflowProtocolSupport {
        workflow: "replay",
        builds: NONE,
        dissects: NONE,
        matches: NONE,
        capture_roots: true,
        packet_independent: false,
        notes: "exact captured frames remain authoritative during bounded replay",
    },
    WorkflowProtocolSupport {
        workflow: "scan",
        builds: PROBE_BUILD,
        dissects: ALL_DISSECT,
        matches: PROBE_MATCHERS,
        capture_roots: true,
        packet_independent: false,
        notes: "scan probes and classifications use shared builders, dissectors, and matchers",
    },
    WorkflowProtocolSupport {
        workflow: "traceroute",
        builds: PROBE_BUILD,
        dissects: ALL_DISSECT,
        matches: PROBE_MATCHERS,
        capture_roots: true,
        packet_independent: false,
        notes: "IPv4/IPv6 UDP, TCP, and ICMP probes use the shared registry contract",
    },
    WorkflowProtocolSupport {
        workflow: "dns",
        builds: DNS_BUILD,
        dissects: DNS_DISSECT,
        matches: DNS_MATCHERS,
        capture_roots: true,
        packet_independent: false,
        notes: "bounded DNS messages are tool-owned payloads; live queries use UDP and the pure TCP frame decoder shares validation without implicit port-based dissection",
    },
    WorkflowProtocolSupport {
        workflow: "fuzz",
        builds: ALL_BUILD,
        dissects: ALL_DISSECT,
        matches: MATCHERS,
        capture_roots: true,
        packet_independent: false,
        notes: "offline field-aware mutation covers every constructible codec; explicit live cases reuse shared matchers and capture roots",
    },
    WorkflowProtocolSupport {
        workflow: "interfaces",
        builds: NONE,
        dissects: NONE,
        matches: NONE,
        capture_roots: false,
        packet_independent: true,
        notes: "passive interface inventory has no packet-layer obligation",
    },
    WorkflowProtocolSupport {
        workflow: "routes",
        builds: NONE,
        dissects: NONE,
        matches: NONE,
        capture_roots: false,
        packet_independent: true,
        notes: "passive route inventory has no packet-layer obligation",
    },
];

/// Stable manifest exported by the crate and serializable by downstream tooling.
pub const BUILTIN_PROTOCOL_SUPPORT: ProtocolSupportManifest = ProtocolSupportManifest {
    schema: PROTOCOL_SUPPORT_SCHEMA_V1,
    protocols: BUILTIN_PROTOCOLS,
    capture_roots: BUILTIN_CAPTURE_ROOTS,
    workflows: STABLE_WORKFLOW_PROTOCOLS,
    fallback: ProtocolFallbackSupport {
        unknown_link_type_as_raw: true,
        unknown_discriminator_as_raw: true,
        strict_known_discriminator_requires_typed_codec: true,
        malformed_bytes_preserved: true,
    },
};

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::Bytes;

    use super::*;
    use crate::packet::{
        field::{FieldKind, FieldValue},
        layer::FieldError,
    };

    fn unique(values: &[&str]) -> bool {
        values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
    }

    fn representative_value(kind: FieldKind, name: &str) -> FieldValue {
        match kind {
            FieldKind::Bool => FieldValue::Bool(true),
            FieldKind::Unsigned => FieldValue::Unsigned(0),
            FieldKind::Signed => FieldValue::Signed(0),
            FieldKind::Text if name == "byte_order" => FieldValue::Text("little".to_owned()),
            FieldKind::Text => FieldValue::Text("value".to_owned()),
            FieldKind::Bytes if name == "address" => FieldValue::Bytes(Bytes::from(vec![0; 8])),
            FieldKind::Bytes => FieldValue::Bytes(Bytes::from_static(&[1, 2])),
            FieldKind::Ipv4 => FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 1)),
            FieldKind::Ipv6 => FieldValue::Ipv6(Ipv6Addr::LOCALHOST),
            FieldKind::Mac => FieldValue::Mac([0, 1, 2, 3, 4, 5]),
            FieldKind::List => FieldValue::List(Vec::new()),
        }
    }

    fn definitely_wrong_value(kind: FieldKind) -> FieldValue {
        if kind == FieldKind::Bool {
            FieldValue::Text("wrong".to_owned())
        } else {
            FieldValue::Bool(false)
        }
    }

    #[test]
    fn every_constructible_builtin_obeys_the_reflective_field_contract() {
        let registry = crate::protocol::builtin::registry().unwrap();
        for support in BUILTIN_PROTOCOLS.iter().filter(|support| support.build) {
            let codec = registry.codec_named(support.protocol).unwrap();
            let layer = codec.make_layer(&BTreeMap::new()).unwrap();
            let schema = layer.schema();
            let names = schema
                .fields
                .iter()
                .map(|field| field.name)
                .collect::<BTreeSet<_>>();
            assert_eq!(
                names.len(),
                schema.fields.len(),
                "{} schema",
                support.protocol
            );

            for layout_name in layer.declared_layout_fields() {
                assert!(
                    names.contains(layout_name),
                    "{} layout field {layout_name} is absent from its schema",
                    support.protocol
                );
            }

            for field in schema.fields {
                let value = representative_value(field.kind, field.name);
                let mut writable = layer.clone_box();
                writable
                    .set_field(field.name, value.clone())
                    .unwrap_or_else(|error| {
                        panic!(
                            "{}.{} rejected its schema type: {error}",
                            support.protocol, field.name
                        )
                    });
                assert_eq!(
                    writable.field(field.name),
                    Some(value),
                    "{}.{} setter/getter round trip",
                    support.protocol,
                    field.name
                );

                let mut wrong = layer.clone_box();
                assert!(
                    matches!(
                        wrong.set_field(field.name, definitely_wrong_value(field.kind)),
                        Err(FieldError::WrongType { .. })
                    ),
                    "{}.{} accepted an incompatible type",
                    support.protocol,
                    field.name
                );
            }

            assert!(matches!(
                layer
                    .clone_box()
                    .set_field("__unknown", FieldValue::Bool(false)),
                Err(FieldError::UnknownField { .. })
            ));
        }
    }

    #[test]
    fn address_fields_preserve_direct_text_setter_conversions() {
        let registry = crate::protocol::builtin::registry().unwrap();

        let mut ipv4 = registry
            .codec_named("ipv4")
            .unwrap()
            .make_layer(&BTreeMap::new())
            .unwrap();
        ipv4.set_field("source", FieldValue::Text("192.0.2.9".to_owned()))
            .unwrap();
        assert_eq!(
            ipv4.field("source"),
            Some(FieldValue::Ipv4(Ipv4Addr::new(192, 0, 2, 9)))
        );
        assert!(matches!(
            ipv4.set_field("source", FieldValue::Text("not-an-address".to_owned())),
            Err(FieldError::WrongType {
                expected: "ipv4",
                ..
            })
        ));

        let mut ipv6 = registry
            .codec_named("ipv6")
            .unwrap()
            .make_layer(&BTreeMap::new())
            .unwrap();
        ipv6.set_field("source", FieldValue::Text("2001:db8::9".to_owned()))
            .unwrap();
        assert_eq!(
            ipv6.field("source"),
            Some(FieldValue::Ipv6("2001:db8::9".parse().unwrap()))
        );

        let mut ethernet = registry
            .codec_named("ethernet")
            .unwrap()
            .make_layer(&BTreeMap::new())
            .unwrap();
        ethernet
            .set_field("source", FieldValue::Text("00-11-22-33-44-55".to_owned()))
            .unwrap();
        assert_eq!(
            ethernet.field("source"),
            Some(FieldValue::Mac([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]))
        );
    }

    #[test]
    fn manifest_matches_the_default_registry_exactly() {
        let registry = crate::protocol::builtin::registry().unwrap();
        let declared = BUILTIN_PROTOCOLS
            .iter()
            .map(|support| (support.protocol, support))
            .collect::<BTreeMap<_, _>>();
        let actual = registry
            .protocols()
            .map(|protocol| protocol.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(declared.keys().copied().collect::<BTreeSet<_>>(), actual);
        assert_eq!(declared.len(), 25);

        for support in BUILTIN_PROTOCOLS {
            let identity = BuiltinProtocol::from_name(support.protocol)
                .expect("manifest protocol must have a catalog identity");
            assert_eq!(identity.aliases(), support.aliases);
            assert_eq!(identity.is_constructible(), support.build);
            assert_eq!(identity.is_dissectible(), support.dissect);
            assert_eq!(identity.has_exact_round_trip(), support.exact_round_trip);
            assert_eq!(identity.has_matcher(), support.matcher);
            assert!(unique(support.aliases), "{} aliases", support.protocol);
            let codec = registry
                .codec(&support.protocol.into())
                .expect("declared protocol must have a codec");
            assert_eq!(
                codec.aliases(),
                support.aliases,
                "{} aliases",
                support.protocol
            );
            let constructed = codec.make_layer(&BTreeMap::new());
            assert_eq!(
                constructed.is_ok(),
                support.build,
                "{} constructibility",
                support.protocol
            );
            if let Ok(layer) = constructed {
                layer
                    .validate_required_fields()
                    .unwrap_or_else(|error| panic!("{} defaults: {error}", support.protocol));
            }
            assert_eq!(
                registry.matcher(&support.protocol.into()).is_some(),
                support.matcher,
                "{} matcher",
                support.protocol
            );
        }
        assert_eq!(
            BUILTIN_PROTOCOLS
                .iter()
                .filter(|support| support.decode_only)
                .map(|support| support.protocol)
                .collect::<Vec<_>>(),
            vec!["raw_ip"]
        );

        let roots = registry
            .link_type_roots()
            .map(|(link_type, protocol)| (link_type, protocol.as_str()))
            .collect::<BTreeMap<_, _>>();
        let declared_roots = BUILTIN_CAPTURE_ROOTS
            .iter()
            .map(|root| (root.link_type, root.protocol))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(declared_roots, roots);

        let matchers = registry
            .matcher_protocols()
            .map(|protocol| protocol.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(matchers, MATCHERS.iter().copied().collect());
    }

    #[test]
    fn every_stable_workflow_has_valid_protocol_obligations() {
        let output_commands = [
            "build",
            "dissect",
            "plan",
            "send",
            "exchange",
            "capture",
            "read",
            "replay",
            "scan",
            "traceroute",
            "dns",
            "fuzz",
            "interfaces",
            "routes",
        ]
        .into_iter()
        .collect::<BTreeSet<_>>();
        let workflow_names = STABLE_WORKFLOW_PROTOCOLS
            .iter()
            .map(|workflow| workflow.workflow)
            .collect::<BTreeSet<_>>();
        assert_eq!(workflow_names, output_commands);
        assert_eq!(workflow_names.len(), 14);

        for workflow in STABLE_WORKFLOW_PROTOCOLS {
            assert!(unique(workflow.builds), "{} build list", workflow.workflow);
            assert!(
                unique(workflow.dissects),
                "{} dissect list",
                workflow.workflow
            );
            assert!(
                unique(workflow.matches),
                "{} matcher list",
                workflow.workflow
            );
            if workflow.packet_independent {
                assert!(workflow.builds.is_empty());
                assert!(workflow.dissects.is_empty());
                assert!(workflow.matches.is_empty());
                assert!(!workflow.capture_roots);
            } else {
                assert!(
                    workflow.capture_roots
                        || !workflow.builds.is_empty()
                        || !workflow.dissects.is_empty()
                        || !workflow.matches.is_empty(),
                    "{} must declare an obligation",
                    workflow.workflow
                );
            }
            for protocol in workflow.builds {
                let support = BUILTIN_PROTOCOLS
                    .iter()
                    .find(|support| support.protocol == *protocol)
                    .expect("workflow build protocol must be declared");
                assert!(
                    support.build,
                    "{} cannot build {protocol}",
                    workflow.workflow
                );
            }
            for protocol in workflow.dissects {
                let support = BUILTIN_PROTOCOLS
                    .iter()
                    .find(|support| support.protocol == *protocol)
                    .expect("workflow dissect protocol must be declared");
                assert!(
                    support.dissect,
                    "{} cannot dissect {protocol}",
                    workflow.workflow
                );
            }
            for protocol in workflow.matches {
                let support = BUILTIN_PROTOCOLS
                    .iter()
                    .find(|support| support.protocol == *protocol)
                    .expect("workflow matcher protocol must be declared");
                assert!(
                    support.matcher,
                    "{} cannot match {protocol}",
                    workflow.workflow
                );
            }
        }

        for name in ["scan", "traceroute"] {
            let workflow = STABLE_WORKFLOW_PROTOCOLS
                .iter()
                .find(|workflow| workflow.workflow == name)
                .unwrap();
            assert_eq!(workflow.builds, PROBE_BUILD);
            assert_eq!(workflow.matches, PROBE_MATCHERS);
            assert!(!workflow.builds.contains(&"gre"));
            assert!(!workflow.builds.contains(&"igmp"));
            assert!(!workflow.builds.contains(&"sctp"));
        }
    }

    #[test]
    fn manifest_serialization_is_versioned_and_complete() {
        let value = serde_json::to_value(BUILTIN_PROTOCOL_SUPPORT).unwrap();
        assert_eq!(value["schema"], PROTOCOL_SUPPORT_SCHEMA_V1);
        assert_eq!(value["protocols"].as_array().unwrap().len(), 25);
        assert_eq!(value["capture_roots"].as_array().unwrap().len(), 9);
        assert_eq!(value["workflows"].as_array().unwrap().len(), 14);
    }

    #[test]
    fn catalog_membership_is_independent_of_live_backend_features() {
        // Backends are feature-gated, but the portable built-in codec catalog
        // is not. This assertion runs in every CI feature profile.
        assert_eq!(BuiltinProtocol::ALL.len(), 25);
        assert_eq!(BUILTIN_PROTOCOLS.len(), BuiltinProtocol::ALL.len());
        assert!(BuiltinProtocol::ALL.contains(&BuiltinProtocol::RawIp));
    }
}
