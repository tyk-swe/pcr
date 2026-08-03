// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Output contract for the `interfaces` command.

pub use crate::output::network::model::{
    InterfaceCapabilityOutput as Capability, InterfaceFlagsOutput as Flags,
    InterfaceOutput as Interface, InterfacesCommandResult as Result,
};
