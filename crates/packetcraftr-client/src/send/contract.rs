// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::net::IpAddr;

use bytes::Bytes;
use thiserror::Error;

use packetcraftr_error::{Category, Classification, Classified, Kind};
use packetcraftr_net::{
    Error as LiveIoError,
    neighbor::Error as NeighborError,
    route::{MaterializedRoute, PlanError, PlanOptions},
};
use packetcraftr_packet::build::{BuildError, BuildOptions, BuiltPacket};

use super::super::Stats;
use super::super::policy::TrafficPolicyError;
use super::super::target::TargetResolutionError;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SendOptions {
    pub destination: Option<IpAddr>,
    pub plan: PlanOptions,
    pub build: BuildOptions,
    /// Second explicit opt-in required in addition to policy approval.
    pub allow_permissive_live: bool,
}

#[derive(Clone, Debug)]
pub struct SendReport {
    pub built: BuiltPacket,
    pub route: MaterializedRoute,
    pub wire_bytes: Bytes,
    pub stats: Stats,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error(transparent)]
    Target(#[from] TargetResolutionError),
    #[error(transparent)]
    Plan(#[from] PlanError),
    #[error(transparent)]
    Neighbor(#[from] NeighborError),
    #[error(transparent)]
    Build(#[from] BuildError),
    #[error(transparent)]
    Decode(#[from] packetcraftr_packet::decode::DecodeError),
    #[error(transparent)]
    Policy(#[from] TrafficPolicyError),
    #[error("permissively built packets require allow_permissive_live")]
    PermissiveLiveOptInRequired,
    #[error(transparent)]
    Io(#[from] LiveIoError),
    #[error("{operation}; capture shutdown also failed: {shutdown}")]
    OperationAndCaptureShutdown {
        operation: LiveIoError,
        shutdown: LiveIoError,
    },
    #[error("exchange packets selected different interfaces or link modes")]
    HeterogeneousExchangeRoute,
    #[error("packet template expansion failed: {message}")]
    Template { message: String },
    #[error("could not materialize {field} on layer {layer}: {message}")]
    PacketMaterialization {
        layer: usize,
        field: &'static str,
        message: String,
    },
    #[error(
        "network packet length {actual} exceeds route MTU {mtu}; apply an explicit fragmentation transform"
    )]
    PacketExceedsMtu { actual: usize, mtu: u32 },
    #[error("invalid exchange option {field}: {message}")]
    InvalidExchangeOption {
        field: &'static str,
        message: String,
    },
}

impl Classified for ClientError {
    fn classification(&self) -> Classification {
        match self {
            Self::Target(error) => error.classification(),
            Self::Plan(error) => error.classification(),
            Self::Neighbor(error) => error.classification(),
            Self::Build(_) => Classification::new(
                "packet.build",
                Kind::Packet,
                Some(
                    "correct the packet fields or select permissive mode with the required live opt-ins",
                ),
            ),
            Self::Decode(_) => Classification::new(
                "packet.decode",
                Kind::Packet,
                Some("inspect the capture link type, packet bytes, and configured decode limits"),
            ),
            Self::Policy(error) => error.classification(),
            Self::PermissiveLiveOptInRequired => Classification::new(
                "policy.permissive_live_opt_in",
                Kind::Policy,
                Some(
                    "set the explicit per-operation malformed-live opt-in in addition to policy approval",
                ),
            ),
            Self::Io(error) => error.classification(),
            Self::OperationAndCaptureShutdown { operation, .. } => {
                operation.classification().with_category(Category::Cleanup)
            }
            Self::HeterogeneousExchangeRoute => Classification::new(
                "cli.heterogeneous_exchange_route",
                Kind::Cli,
                Some("split the exchange so every packet uses the same interface and link mode"),
            ),
            Self::Template { .. } => Classification::new(
                "packet.template",
                Kind::Packet,
                Some("reduce or correct the bounded packet-template expansion"),
            ),
            Self::PacketMaterialization { .. } => Classification::new(
                "packet.materialization",
                Kind::Packet,
                Some(
                    "correct the route-dependent packet fields; post-build shape changes are rejected",
                ),
            ),
            Self::PacketExceedsMtu { .. } => Classification::new(
                "packet.mtu",
                Kind::Packet,
                Some("reduce the network packet or apply an explicit fragmentation transform"),
            ),
            Self::InvalidExchangeOption { .. } => Classification::new(
                "cli.exchange_limit",
                Kind::Cli,
                Some(
                    "use finite exchange timeout and retention limits no larger than the aggregate capture ceiling",
                ),
            ),
        }
    }

    fn causes(&self) -> Vec<String> {
        match self {
            Self::Target(error) => error.causes(),
            Self::Plan(error) => error.causes(),
            Self::Neighbor(error) => error.causes(),
            Self::Policy(error) => error.causes(),
            Self::Io(error) => error.causes(),
            Self::OperationAndCaptureShutdown {
                operation,
                shutdown,
            } => vec![operation.to_string(), shutdown.to_string()],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use packetcraftr_error::{Category, Classified, Kind};

    use super::{ClientError, SendOptions};
    use crate::policy::TrafficPolicyError;
    use packetcraftr_net::Error as LiveIoError;

    #[test]
    fn default_send_options_are_conservative() {
        let options = SendOptions::default();
        assert_eq!(options.destination, None);
        assert!(!options.allow_permissive_live);
        assert_eq!(options.plan, Default::default());
        assert_eq!(options.build, Default::default());
    }

    #[test]
    fn client_owned_error_variants_have_stable_classifications() {
        let cases = [
            (
                ClientError::PermissiveLiveOptInRequired,
                "policy.permissive_live_opt_in",
                Kind::Policy,
            ),
            (
                ClientError::HeterogeneousExchangeRoute,
                "cli.heterogeneous_exchange_route",
                Kind::Cli,
            ),
            (
                ClientError::Template {
                    message: "too large".to_owned(),
                },
                "packet.template",
                Kind::Packet,
            ),
            (
                ClientError::PacketMaterialization {
                    layer: 1,
                    field: "source",
                    message: "missing".to_owned(),
                },
                "packet.materialization",
                Kind::Packet,
            ),
            (
                ClientError::PacketExceedsMtu {
                    actual: 1_501,
                    mtu: 1_500,
                },
                "packet.mtu",
                Kind::Packet,
            ),
            (
                ClientError::InvalidExchangeOption {
                    field: "timeout",
                    message: "must be finite".to_owned(),
                },
                "cli.exchange_limit",
                Kind::Cli,
            ),
        ];

        for (error, code, kind) in cases {
            let classification = error.classification();
            assert_eq!(classification.code, code);
            assert_eq!(classification.kind, kind);
            assert!(classification.remediation.is_some());
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn wrapped_policy_and_live_io_errors_preserve_their_classification() {
        let policy = ClientError::Policy(TrafficPolicyError::PacketLimit {
            actual: 2,
            limit: 1,
        });
        assert_eq!(policy.classification().code, "policy.packet_limit");

        let io = ClientError::Io(LiveIoError::Privilege {
            message: "denied".to_owned(),
        });
        assert_eq!(io.classification().code, "capability.privilege");
    }

    #[test]
    fn cleanup_failure_preserves_operation_classification_and_both_causes() {
        let error = ClientError::OperationAndCaptureShutdown {
            operation: LiveIoError::Send {
                message: "send failed".to_owned(),
            },
            shutdown: LiveIoError::Capture {
                message: "shutdown failed".to_owned(),
            },
        };
        let classification = error.classification();
        assert_eq!(classification.code, "io.send");
        assert_eq!(classification.kind, Kind::Io);
        assert_eq!(classification.category, Category::Cleanup);
        assert_eq!(
            error.causes(),
            vec![
                "packet transmission failed: send failed".to_owned(),
                "capture failed: shutdown failed".to_owned(),
            ]
        );
    }

    #[test]
    fn client_owned_errors_have_no_nested_causes() {
        assert!(
            ClientError::Template {
                message: "invalid".to_owned(),
            }
            .causes()
            .is_empty()
        );
    }
}
