// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Pure-Rust, streaming PCAP and PCAPNG support.
//!
//! The implementation deliberately depends only on [`std::io`].  Native
//! libpcap/Npcap is a live-I/O concern and is not required for reading or
//! writing capture files.

use std::fmt;
use std::io::{self, Read, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::error::{Classification, Classified, Kind};

use super::{Direction, Frame, LinkType};

// The capture container implementation is split by responsibility while these
// fragments retain one private scope. That keeps parsing and writing helpers
// private without changing the public capture API or any wire behavior.
include!("wire.rs");
include!("models.rs");
include!("reader.rs");
include!("classic.rs");
include!("pcapng.rs");
include!("writer.rs");
include!("transcode.rs");
include!("tests.rs");
