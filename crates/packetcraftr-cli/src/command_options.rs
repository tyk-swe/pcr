// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) use address_family::AddressFamily;
pub(crate) use capture_limits::CaptureLimitsArgs;
pub(crate) use decode::DecodeArgs;
pub(crate) use epoch_bounds::EpochBoundsArgs;
pub(crate) use offline_limits::{
    AnalysisStages, CaptureReaderBoundsArgs, OfflineCaptureLimitsArgs, OfflineLimitsArgs,
};
pub(crate) use packet_budget::PacketBudgetArgs;
pub(crate) use policy::{
    Budget, DestinationAllowlistArgs, HostnamePolicyArgs, HostnameResolutionArgs,
    PermissivePacketArgs, PublicDestinationArgs, SendPolicyArgs, SourceSpoofingArgs,
    TrafficBudgetArgs, Transmitted, default_limit_bytes,
};
pub(crate) use recipe::{BuildMode, RecipeArgs};
pub(crate) use route::{LinkMode, RouteArgs, RouteSelectionArgs};
pub(crate) use send::SendArgs;
pub(crate) use template::TemplateArgs;

mod address_family;
mod capture_limits;
mod decode;
mod epoch_bounds;
mod offline_limits;
mod packet_budget;
mod policy;
mod recipe;
mod route;
mod send;
mod template;

mod compression;
pub(crate) use compression::{
    CaptureStdout, Compression, CompressionArgs, Destination, SavedPcapNg,
};

mod duration;
pub(crate) use duration::{
    Bounded, MAX_MILLISECONDS as MAX_DURATION_MILLISECONDS, MaxDurationArgs, ProbeWindow, Probing,
    RunTime, TimeoutArgs, Window,
};

mod selectors;
pub(crate) use selectors::{InterfaceSelector, Selector, interface_selector, stream_selector};

mod target;
pub(crate) use target::parse_target;

mod timestamp;
pub(crate) use timestamp::parse_timestamp;

mod application;
pub(crate) use application::{ApplicationLimitsArgs, validate_output_bytes};
