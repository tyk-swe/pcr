// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

pub(crate) use address_family::AddressFamily;
pub(crate) use capture_limits::CaptureLimitsArgs;
pub(crate) use decode::DecodeArgs;
pub(crate) use epoch_bounds::EpochBoundsArgs;
pub(crate) use frame_ranges::{FrameSelection, FrameSelectionArgs};
pub(crate) use offline_limits::{
    AnalysisStages, CaptureReaderBoundsArgs, OfflineCaptureLimitsArgs, OfflineLimitsArgs,
};
pub(crate) use packet_budget::PacketBudgetArgs;
pub(crate) use policy::{
    DestinationAllowlistArgs, HostnamePolicyArgs, HostnameResolutionArgs, IdentificationPolicyArgs,
    NumericPolicyArgs, PublicDestinationArgs, SendPolicyArgs, TrafficBudgetArgs,
};
pub(crate) use recipe::{BuildMode, RecipeArgs};
pub(crate) use route::{LinkMode, RouteArgs, RouteSelectionArgs};
pub(crate) use send::SendArgs;
pub(crate) use template::{TemplateArgs, bytes_held};
pub(crate) use tree::TreeArgs;

mod address_family;
mod capture_limits;
mod decode;
mod epoch_bounds;
mod frame_ranges;
pub(crate) mod link_type;
mod offline_limits;
mod packet_budget;
mod policy;
mod recipe;
mod route;
mod send;
mod template;
mod tree;

mod compression;
pub(crate) use compression::{Compression, CompressionArgs};

mod duration;
pub(crate) use duration::{Bounded, LongTimeoutArgs, MaxDurationArgs, TimeoutArgs};

mod selectors;
pub(crate) use selectors::{InterfaceSelector, Selector, interface_selector, stream_selector};

mod timestamp;
pub(crate) use timestamp::parse_timestamp;

mod application;
pub(crate) use application::{ApplicationLimitsArgs, validate_output_bytes};

pub(crate) fn parse_target(
    target: String,
) -> Result<packetcraftr::target::Target, crate::errors::CliError> {
    target
        .parse::<packetcraftr::target::Target>()
        .map_err(crate::errors::CliError::classified)
}
