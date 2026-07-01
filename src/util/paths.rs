// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::env;
use std::path::PathBuf;

const HISTORY_FILE: &str = "repl_history";

pub(crate) fn packetcraftr_home_dir() -> PathBuf {
    env::var("PACKETCRAFTR_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(".packetcraftr"))
}

pub(crate) fn repl_history_path() -> PathBuf {
    packetcraftr_home_dir().join(HISTORY_FILE)
}

pub(crate) fn config_dir() -> PathBuf {
    packetcraftr_home_dir().join("config")
}

pub(crate) fn data_dir() -> PathBuf {
    packetcraftr_home_dir().join("data")
}
