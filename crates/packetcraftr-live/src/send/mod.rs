// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Single-packet send contracts.

pub(crate) mod contract;
pub(crate) mod execution;

pub(crate) use contract::{ClientError, SendOptions, SendReport, SentPacket};
pub use contract::{SendOptions as Options, SendReport as Report, SentPacket as Receipt};
