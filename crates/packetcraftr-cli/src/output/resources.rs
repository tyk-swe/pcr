// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Opt-in resource metadata in the existing output envelope. Domain reports
//! and classified errors remain the authoritative work/loss counters.

use serde::Serialize;

/// A reported resource value: a measured count or a policy-bound text form.
#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Value {
    Number(u64),
    Policy(String),
}

/// One effective option, including its resource scope and provenance.
#[derive(Clone, Debug, Serialize)]
pub struct Setting {
    pub name: String,
    pub value: Value,
    pub unit: String,
    pub stage: String,
    pub scope: String,
    pub source: String,
    /// Whether the selected command/transport enables this stage.
    pub enabled: bool,
}

/// One admission owner's diagnostic sample. Active includes retained cleanup.
#[derive(Clone, Debug, Serialize)]
pub struct Worker {
    pub name: String,
    pub supported: bool,
    pub capacity: usize,
    pub active: usize,
    pub rejected_admissions: usize,
    pub cleanup_retaining_capacity: usize,
}

/// A callback runtime's admission sample, under its assembly owner's name.
impl From<(&str, packetcraftr::runtime::RuntimeSnapshot)> for Worker {
    fn from((name, snapshot): (&str, packetcraftr::runtime::RuntimeSnapshot)) -> Self {
        Self {
            name: name.to_owned(),
            supported: true,
            capacity: snapshot.capacity,
            active: snapshot.active,
            rejected_admissions: snapshot.rejected_admissions,
            cleanup_retaining_capacity: snapshot.timed_out_retaining_capacity,
        }
    }
}

/// A native worker pool's admission sample, under the name it is published as.
impl From<(&str, packetcraftr_netio::resources::NativeSnapshot)> for Worker {
    fn from((name, snapshot): (&str, packetcraftr_netio::resources::NativeSnapshot)) -> Self {
        Self {
            name: name.to_owned(),
            supported: snapshot.supported,
            capacity: snapshot.capacity,
            active: snapshot.active,
            rejected_admissions: snapshot.rejected_admissions,
            cleanup_retaining_capacity: snapshot.cleanup_retaining_capacity,
        }
    }
}

/// Configuration and admission observations; never an RSS guarantee. Per-stage
/// usage/loss remains in the command result and its existing error codes.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub settings: Vec<Setting>,
    pub workers: Vec<Worker>,
    pub cooperative_deadlines: bool,
    pub hard_rss_limit: bool,
}
