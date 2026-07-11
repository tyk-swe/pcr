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
    pub wire_bytes: Option<Bytes>,
    pub stats: OperationStats,
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
    Decode(#[from] crate::packet::internal::DecodeError),
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
    #[error("network packet length {actual} exceeds route MTU {mtu}; apply an explicit fragmentation transform")]
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
                Some("correct the packet fields or select permissive mode with the required live opt-ins"),
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
                Some("set the explicit per-operation malformed-live opt-in in addition to policy approval"),
            ),
            Self::Io(error) => error.classification(),
            Self::OperationAndCaptureShutdown { operation, .. } => operation
                .classification()
                .with_category(Category::Cleanup),
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
                Some("correct the route-dependent packet fields; post-build shape changes are rejected"),
            ),
            Self::PacketExceedsMtu { .. } => Classification::new(
                "packet.mtu",
                Kind::Packet,
                Some("reduce the network packet or apply an explicit fragmentation transform"),
            ),
            Self::InvalidExchangeOption { .. } => Classification::new(
                "cli.exchange_limit",
                Kind::Cli,
                Some("use finite exchange timeout and retention limits no larger than the aggregate capture ceiling"),
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
