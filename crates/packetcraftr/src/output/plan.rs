// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `plan` command.

use serde::Serialize;

use crate::output::network::PlannedRouteOutput;
pub use crate::output::network::{
    InterfaceCapabilityOutput as Capability, PlannedRouteOutput as Plan,
    RouteDecisionOutput as Decision, RouteInterfaceOutput as Interface,
    RouteMacAddressOutput as MacAddress, RouteModeOutput as Mode, RouteScopeOutput as Scope,
    RouteSelectionOutput as SelectionReason, RouteVlanKindOutput as VlanKind,
    RouteVlanTagOutput as VlanTag,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PlanCommandResult {
    pub route: PlannedRouteOutput,
}
