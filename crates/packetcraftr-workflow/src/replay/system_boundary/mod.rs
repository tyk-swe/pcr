// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Production authorization and transmission boundaries for live replay.

mod authorization;
mod transmission;

pub use authorization::SystemAuthorizer;
pub use transmission::SystemTransmitter;
