// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Versioned public contract for built-in codecs, capture roots, and stable workflows.

use serde::Serialize;

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

macro_rules! protocol {
    ($name:literal, $aliases:expr, matcher = $matcher:literal) => {
        ProtocolSupport {
            protocol: $name,
            aliases: $aliases,
            build: true,
            dissect: true,
            exact_round_trip: true,
            matcher: $matcher,
            decode_only: false,
        }
    };
}

/// All 22 codecs registered by [`super::BuiltinProtocols`].
pub const BUILTIN_PROTOCOLS: &[ProtocolSupport] = &[
    protocol!("arp", &[], matcher = false),
    protocol!("bsd_loop", &["loop"], matcher = false),
    protocol!("bsd_null", &["null"], matcher = false),
    protocol!("ethernet", &["eth", "ether", "ethernet2"], matcher = false),
    protocol!("icmpv4", &["icmp", "icmp4"], matcher = true),
    protocol!("icmpv6", &["icmp6"], matcher = true),
    protocol!("ipv4", &["ip", "ip4"], matcher = false),
    protocol!("ipv6", &["ip6"], matcher = false),
    protocol!(
        "ipv6_destination_options",
        &["destopts", "destination_options"],
        matcher = false
    ),
    protocol!("ipv6_fragment", &["fragment6", "frag6"], matcher = false),
    protocol!(
        "ipv6_hop_by_hop",
        &["hop", "hopopts", "hbh"],
        matcher = false
    ),
    protocol!("ipv6_srh", &["srh", "segment_routing"], matcher = false),
    protocol!("linux_sll", &["sll"], matcher = false),
    protocol!("linux_sll2", &["sll2"], matcher = false),
    protocol!("malformed", &[], matcher = false),
    protocol!("padding", &["pad"], matcher = false),
    protocol!("raw", &["payload", "bytes"], matcher = false),
    ProtocolSupport {
        protocol: "raw_ip",
        aliases: &["rawip"],
        build: false,
        dissect: true,
        exact_round_trip: true,
        matcher: false,
        decode_only: true,
    },
    protocol!("tcp", &[], matcher = true),
    protocol!("udp", &[], matcher = true),
    protocol!("vlan", &["dot1q", "8021q"], matcher = false),
    protocol!("vlan8021ad", &["dot1ad", "8021ad", "qinq"], matcher = false),
];

/// Every numeric capture root registered by the default built-in module.
pub const BUILTIN_CAPTURE_ROOTS: &[CaptureRootSupport] = &[
    CaptureRootSupport {
        link_type: 0,
        protocol: "bsd_null",
        byte_order: CaptureRootByteOrder::CapturedHost,
        exact_round_trip: true,
    },
    CaptureRootSupport {
        link_type: super::LINKTYPE_ETHERNET,
        protocol: "ethernet",
        byte_order: CaptureRootByteOrder::ProtocolDefined,
        exact_round_trip: true,
    },
    CaptureRootSupport {
        link_type: super::DLT_RAW,
        protocol: "raw_ip",
        byte_order: CaptureRootByteOrder::ProtocolDefined,
        exact_round_trip: true,
    },
    CaptureRootSupport {
        link_type: super::LINKTYPE_RAW,
        protocol: "raw_ip",
        byte_order: CaptureRootByteOrder::ProtocolDefined,
        exact_round_trip: true,
    },
    CaptureRootSupport {
        link_type: 108,
        protocol: "bsd_loop",
        byte_order: CaptureRootByteOrder::Network,
        exact_round_trip: true,
    },
    CaptureRootSupport {
        link_type: 113,
        protocol: "linux_sll",
        byte_order: CaptureRootByteOrder::Network,
        exact_round_trip: true,
    },
    CaptureRootSupport {
        link_type: super::LINKTYPE_IPV4,
        protocol: "ipv4",
        byte_order: CaptureRootByteOrder::ProtocolDefined,
        exact_round_trip: true,
    },
    CaptureRootSupport {
        link_type: super::LINKTYPE_IPV6,
        protocol: "ipv6",
        byte_order: CaptureRootByteOrder::ProtocolDefined,
        exact_round_trip: true,
    },
    CaptureRootSupport {
        link_type: 276,
        protocol: "linux_sll2",
        byte_order: CaptureRootByteOrder::Network,
        exact_round_trip: true,
    },
];

const NONE: &[&str] = &[];
const MATCHERS: &[&str] = &["icmpv4", "icmpv6", "tcp", "udp"];
const DNS_MATCHERS: &[&str] = &["tcp", "udp"];
const ALL_BUILD: &[&str] = &[
    "arp",
    "bsd_loop",
    "bsd_null",
    "ethernet",
    "icmpv4",
    "icmpv6",
    "ipv4",
    "ipv6",
    "ipv6_destination_options",
    "ipv6_fragment",
    "ipv6_hop_by_hop",
    "ipv6_srh",
    "linux_sll",
    "linux_sll2",
    "malformed",
    "padding",
    "raw",
    "tcp",
    "udp",
    "vlan",
    "vlan8021ad",
];
const ALL_DISSECT: &[&str] = &[
    "arp",
    "bsd_loop",
    "bsd_null",
    "ethernet",
    "icmpv4",
    "icmpv6",
    "ipv4",
    "ipv6",
    "ipv6_destination_options",
    "ipv6_fragment",
    "ipv6_hop_by_hop",
    "ipv6_srh",
    "linux_sll",
    "linux_sll2",
    "malformed",
    "padding",
    "raw",
    "raw_ip",
    "tcp",
    "udp",
    "vlan",
    "vlan8021ad",
];
const LIVE_BUILD: &[&str] = &[
    "arp",
    "ethernet",
    "icmpv4",
    "icmpv6",
    "ipv4",
    "ipv6",
    "ipv6_destination_options",
    "ipv6_fragment",
    "ipv6_hop_by_hop",
    "ipv6_srh",
    "malformed",
    "padding",
    "raw",
    "tcp",
    "udp",
    "vlan",
    "vlan8021ad",
];
const DNS_BUILD: &[&str] = &[
    "ethernet",
    "ipv4",
    "ipv6",
    "raw",
    "tcp",
    "udp",
    "vlan",
    "vlan8021ad",
];
const DNS_DISSECT: &[&str] = &[
    "ethernet",
    "ipv4",
    "ipv6",
    "malformed",
    "raw",
    "tcp",
    "udp",
    "vlan",
    "vlan8021ad",
];

/// Packet-layer obligations for every command in the stable v0.2 CLI surface.
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
        builds: LIVE_BUILD,
        dissects: ALL_DISSECT,
        matches: MATCHERS,
        capture_roots: true,
        packet_independent: false,
        notes: "scan probes and classifications use shared builders, dissectors, and matchers",
    },
    WorkflowProtocolSupport {
        workflow: "traceroute",
        builds: LIVE_BUILD,
        dissects: ALL_DISSECT,
        matches: MATCHERS,
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
        matches: NONE,
        capture_roots: false,
        packet_independent: false,
        notes: "offline field-aware mutation uses every constructible codec by default",
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

    use super::*;

    fn unique(values: &[&str]) -> bool {
        values.iter().copied().collect::<BTreeSet<_>>().len() == values.len()
    }

    #[test]
    fn manifest_matches_the_default_registry_exactly() {
        let registry = crate::protocols::default_registry().unwrap();
        let declared = BUILTIN_PROTOCOLS
            .iter()
            .map(|support| (support.protocol, support))
            .collect::<BTreeMap<_, _>>();
        let actual = registry
            .protocols()
            .map(|protocol| protocol.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(declared.keys().copied().collect::<BTreeSet<_>>(), actual);
        assert_eq!(declared.len(), 22);

        for support in BUILTIN_PROTOCOLS {
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
            assert_eq!(
                codec.make_layer(&BTreeMap::new()).is_ok(),
                support.build,
                "{} constructibility",
                support.protocol
            );
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
        let output_commands = crate::output::COMMAND_OUTPUT_CONTRACTS
            .iter()
            .map(|contract| contract.command.as_str())
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
    }

    #[test]
    fn manifest_serialization_is_versioned_and_complete() {
        let value = serde_json::to_value(BUILTIN_PROTOCOL_SUPPORT).unwrap();
        assert_eq!(value["schema"], PROTOCOL_SUPPORT_SCHEMA_V1);
        assert_eq!(value["protocols"].as_array().unwrap().len(), 22);
        assert_eq!(value["capture_roots"].as_array().unwrap().len(), 9);
        assert_eq!(value["workflows"].as_array().unwrap().len(), 14);
    }

    #[test]
    fn published_documentation_covers_the_versioned_manifest() {
        let matrix = include_str!("../../docs/protocol-support.md");
        for support in BUILTIN_PROTOCOLS {
            assert!(
                matrix.contains(&format!("| `{}` |", support.protocol)),
                "documentation is missing protocol {}",
                support.protocol
            );
        }
        for root in BUILTIN_CAPTURE_ROOTS {
            assert!(
                matrix.contains(&format!("| {} | `{}` |", root.link_type, root.protocol)),
                "documentation is missing link type {}",
                root.link_type
            );
        }
        for workflow in STABLE_WORKFLOW_PROTOCOLS {
            assert!(
                matrix.contains(&format!("| `{}` |", workflow.workflow)),
                "documentation is missing workflow {}",
                workflow.workflow
            );
        }

        for document in [
            include_str!("../../README.md"),
            include_str!("../../docs/platform-support.md"),
        ] {
            let lower = document.to_ascii_lowercase();
            assert!(!lower.contains("built-in protocol coverage is incomplete"));
            assert!(!lower.contains("built-in protocol slice remains incomplete"));
        }
    }
}
