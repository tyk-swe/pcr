//! Structured network-operation output.

mod model;

pub mod interfaces {
    pub use super::model::{
        InterfaceCapabilityOutput as Capability, InterfaceFlagsOutput as Flags,
        InterfaceOutput as Interface, InterfacesCommandResult as Result,
    };
}

pub mod plan {
    pub use super::model::{
        PlanCommandResult as Result, PlannedRouteOutput as Plan,
        RouteCapabilityOutput as Capability, RouteDecisionOutput as Decision,
        RouteInterfaceOutput as Interface, RouteMacAddressOutput as MacAddress,
        RouteModeOutput as Mode, RouteScopeOutput as Scope,
        RouteSelectionOutput as SelectionReason, RouteVlanKindOutput as VlanKind,
        RouteVlanTagOutput as VlanTag,
    };
}

pub mod routes {
    pub use super::model::{RouteDecisionOutput as Decision, RoutesCommandResult as Result};
}

pub mod send {
    pub use super::model::{
        MaterializedRouteOutput as MaterializedRoute, NeighborEvidenceOutput as NeighborEvidence,
        SendCommandResult as Result,
    };
}

pub mod exchange {
    pub use super::model::{
        ExchangeCommandResult as Result, ExchangeResponseOutput as Response,
        ExchangeStreamCommandResult as Event,
    };
}
