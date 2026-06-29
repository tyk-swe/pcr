// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

use std::fs::{self, OpenOptions};
use std::io::Write as IoWrite;
use std::path::Path;

use env_logger::{Builder, Target};
use log::LevelFilter;
use serde_json::json;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoggingInitError {
    #[error("create log directory failed: path={}", path.display())]
    CreateLogDirectory {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("open log file failed: path={}", path.display())]
    OpenLogFile {
        path: std::path::PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("initialize env_logger failed: {0}")]
    LoggerInit(#[from] log::SetLoggerError),
}

pub type Result<T> = std::result::Result<T, LoggingInitError>;

pub fn init(
    verbose: u8,
    level_override: Option<LevelFilter>,
    structured: bool,
    log_file: Option<&Path>,
) -> Result<()> {
    let mut builder = Builder::new();
    let base_level = level_override.unwrap_or_else(|| level_from_verbosity(verbose));
    builder.filter_level(base_level);

    if let Some(path) = log_file {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| {
                    LoggingInitError::CreateLogDirectory {
                        path: parent.to_path_buf(),
                        source,
                    }
                })?;
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|source| LoggingInitError::OpenLogFile {
                path: path.to_path_buf(),
                source,
            })?;
        builder.target(Target::Pipe(Box::new(file)));
    }

    if structured {
        builder.format(|buf, record| {
            let timestamp = buf.timestamp().to_string();
            let event = json!({
                "timestamp": timestamp,
                "level": record.level().to_string().to_lowercase(),
                "target": record.target(),
                "message": record.args().to_string(),
            });
            let line = event.to_string();
            buf.write_all(line.as_bytes())?;
            buf.write_all(b"\n")?;
            Ok(())
        });
    }

    builder.try_init().map_err(LoggingInitError::from)?;
    Ok(())
}

fn level_from_verbosity(verbose: u8) -> LevelFilter {
    match verbose {
        0 | 1 => LevelFilter::Info,
        2 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}
