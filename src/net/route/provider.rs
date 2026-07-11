/// Errors emitted by the current target's passive route/interface adapter.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum NativeRouteError {
    #[error("native route selection is unavailable: {message}")]
    Unsupported { message: String },
    #[error("no route to {destination} was found")]
    RouteNotFound { destination: IpAddr },
    #[error("interface {name} (index {index}) was not found")]
    InterfaceNotFound { name: String, index: u32 },
    #[error(
        "interface preference {requested} (index {requested_index}) resolved to {actual} (index {actual_index})"
    )]
    InterfaceMismatch {
        requested: String,
        requested_index: u32,
        actual: String,
        actual_index: u32,
    },
    #[error("preferred source {preferred_source} has a different address family than destination {destination}")]
    SourceFamilyMismatch {
        preferred_source: IpAddr,
        destination: IpAddr,
    },
    #[error("preferred source {preferred_source} is not assigned to interface {interface}")]
    SourceUnavailable {
        preferred_source: IpAddr,
        interface: String,
    },
    #[error("native route response was invalid: {message}")]
    InvalidResponse { message: String },
    #[error("native operation {operation} failed: {message}")]
    OperatingSystem {
        operation: &'static str,
        message: String,
    },
}

/// Route provider backed by the adapter selected for the current target and
/// the explicit `native-route` feature.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemRouteProvider;

impl RouteProvider for SystemRouteProvider {
    type Error = NativeRouteError;

    fn lookup(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
    ) -> Result<RouteDecision, Self::Error> {
        super::platform::system_route(destination, interface_hint, None)
    }

    fn lookup_with_preferences(
        &self,
        destination: IpAddr,
        interface_hint: Option<&InterfaceId>,
        preferred_source: Option<IpAddr>,
    ) -> Result<RouteDecision, Self::Error> {
        super::platform::system_route(destination, interface_hint, preferred_source)
    }

    fn lookup_interface(
        &self,
        interface: &InterfaceId,
    ) -> Result<Option<RouteDecision>, Self::Error> {
        super::platform::system_interface_route(interface).map(Some)
    }

    fn classify_error(&self, error: &Self::Error) -> Classification {
        error.classification()
    }
}

impl Classified for NativeRouteError {
    fn classification(&self) -> Classification {
        match self {
            Self::Unsupported { .. } => Classification::new(
                "capability.route",
                Kind::Capability,
                Some("enable the native-route capability on a supported target or inject a route provider"),
            ),
            Self::RouteNotFound { .. } => Classification::new(
                "io.route_not_found",
                Kind::Io,
                Some("add or select a route for the destination; PacketcraftR will not fall back to another link mode"),
            ),
            Self::InterfaceNotFound { .. } => Classification::new(
                "io.interface_not_found",
                Kind::Io,
                Some("select an existing interface using its current name and index"),
            ),
            Self::InterfaceMismatch { .. }
            | Self::SourceFamilyMismatch { .. }
            | Self::SourceUnavailable { .. } => Classification::new(
                "io.route_selection",
                Kind::Io,
                Some("choose an interface-owned source and interface compatible with the destination family"),
            ),
            Self::InvalidResponse { .. } => Classification::new(
                "internal.route_response",
                Kind::Internal,
                Some("report the invalid native route response; do not use it for transmission"),
            ),
            Self::OperatingSystem { .. } => Classification::new(
                "io.route",
                Kind::Io,
                Some("inspect the operating-system route diagnostic and current network configuration"),
            ),
        }
    }
}
