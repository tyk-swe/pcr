// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Private implementation vocabulary for versioned output contracts.

#![forbid(unsafe_code)]

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::capture::Frame;
use crate::client::{exchange::Result as ExchangeResult, send::Report as SendReport};
use crate::error::{Classification, Classified, Kind};
use crate::net::{
    interface::{Flags as InterfaceFlags, Id as InterfaceId, Info as InterfaceInfo},
    link::{Capability as LinkCapability, Mode as LinkMode},
    route::{Decision as RouteDecision, Materialized as MaterializedRoute, Plan as PlannedRoute},
};
use crate::packet::internal::{
    BuiltPacket, DecodedPacket, Diagnostic, PacketDocument, PacketLayout,
};
use crate::workflow::{
    dns::{
        Edns as DnsEdns, EdnsOption as DnsEdnsOption, Record as DnsRecord,
        RecordValue as DnsRecordValue, Result as DnsResult,
    },
    fuzz::Result as FuzzResult,
    replay::{FrameEvidence as ReplayFrameEvidence, Summary as ReplaySummary},
    scan::Result as ScanResult,
    traceroute::Result as TracerouteResult,
};

// Output-v1 is physically organized by serialized contract responsibility.
// The fragments deliberately share this private module scope so the split
// cannot alter type paths, conversion visibility, or serialized behavior.
include!("common.rs");
include!("contract.rs");
include!("envelope.rs");
include!("frame.rs");
include!("build.rs");
include!("dissect.rs");
include!("capture.rs");
include!("network.rs");
include!("replay.rs");
include!("scan.rs");
include!("traceroute.rs");
include!("dns.rs");
include!("fuzz.rs");
include!("tests.rs");
