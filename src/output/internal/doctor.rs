/// Readiness state reported by `packetcraftr doctor`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorReadiness {
    Ready,
    NotBuilt,
    Unverified,
    Unavailable,
}

impl DoctorReadiness {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::NotBuilt => "not_built",
            Self::Unverified => "unverified",
            Self::Unavailable => "unavailable",
        }
    }
}

/// One independently actionable doctor capability check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorCapability {
    pub name: String,
    pub status: DoctorReadiness,
    pub detail: String,
}

/// Passive platform inventory and optional capture-readiness probe.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DoctorCommandResult {
    pub version: String,
    pub build_target: String,
    pub platform: String,
    pub compiled_features: Vec<String>,
    pub interfaces: Vec<InterfaceOutput>,
    pub routes: Vec<RouteDecisionOutput>,
    pub capabilities: Vec<DoctorCapability>,
    pub capture_probe_attempted: bool,
}
