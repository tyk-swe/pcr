// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

#![cfg(packetcraftr_test_dev_full)]

mod common;

use common::{path_text, run};

#[test]
fn documentation_reports_completion_write_failures_without_panicking() {
    common::require_dev_full();
    for file in [
        "packetcraftr.bash",
        "packetcraftr.elv",
        "packetcraftr.fish",
        "_packetcraftr.ps1",
        "_packetcraftr",
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let completions = temporary.path().join("completions");
        std::fs::create_dir(&completions).unwrap();
        std::os::unix::fs::symlink("/dev/full", completions.join(file)).unwrap();

        let output = run(&["documentation", "--directory", path_text(temporary.path())]);
        assert_eq!(output.status.code(), Some(5), "{file}: {output:?}");
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(
            stderr.contains("error[io.documentation]"),
            "{file}: {stderr}"
        );
        assert!(
            stderr.contains("No space left on device"),
            "{file}: {stderr}"
        );
        assert!(!stderr.contains("panicked"), "{file}: {stderr}");
    }
}
