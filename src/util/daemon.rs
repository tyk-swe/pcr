// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(not(unix))]
use anyhow::bail;
use anyhow::{Context, Result};
use log::info;

/// Ensure the current process is running in the desired daemon mode.
///
/// When `foreground` is `false`, the process detaches using the `daemonize` crate
/// (Unix platforms only). On unsupported platforms the caller receives an error
/// instructing them to use foreground mode instead.
pub fn ensure_daemonized(foreground: bool) -> Result<()> {
    if foreground {
        info!("Running daemon in foreground mode");
        return Ok(());
    }

    #[cfg(unix)]
    {
        use daemonize::Daemonize;

        let current_dir = std::env::current_dir()
            .context("failed to get current working directory for daemon configuration")?;

        // Daemonize defaults: redirect stdout/stderr to /dev/null, change CWD to /
        let daemonize = Daemonize::new().working_directory(current_dir).umask(0o027);

        daemonize
            .start()
            .map_err(|e| anyhow::anyhow!("daemonize process failed: {}", e))?;

        info!(
            "Daemon detached from terminal; continuing in background with pid {}",
            std::process::id()
        );
        Ok(())
    }

    #[cfg(not(unix))]
    {
        bail!("daemon mode is only supported on Unix platforms; rerun with --foreground");
    }
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod tests;
