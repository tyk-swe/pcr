// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![forbid(unsafe_code)]

use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::capture::{Frame, LinkType};
use crate::error::{Category, Classification, Classified, Kind};
use crate::packet::internal::{FieldValue, Packet, ProtocolId};

use super::provider_impl::{CaptureStatistics, LiveIoError};

// These responsibility fragments intentionally share this module scope. The
// route planner's private helpers are part of one implementation contract, and
// keeping the scope flat avoids widening them merely to support the file split.
include!("models.rs");
include!("provider.rs");
include!("planner.rs");
include!("tests.rs");
