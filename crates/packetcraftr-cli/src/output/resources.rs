// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
#[serde(untagged)]
pub enum Value {
    Number(u64),
    Policy(String),
}

#[derive(Clone, Debug, Serialize)]
pub struct Setting {
    pub name: String,
    pub value: Value,
    pub unit: String,
    pub stage: String,
    pub scope: String,
    pub source: String,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Worker {
    pub name: String,
    pub supported: bool,
    pub capacity: usize,
    pub active: usize,
    pub rejected_admissions: usize,
    pub cleanup_retaining_capacity: usize,
}

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

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub settings: Vec<Setting>,
    pub workers: Vec<Worker>,
    pub cooperative_deadlines: bool,
    pub hard_rss_limit: bool,
}
