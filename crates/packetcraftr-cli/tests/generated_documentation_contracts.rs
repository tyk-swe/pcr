// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::{path_text, run, run_success};

/// The `Commands:` section of `--help` is the clap-published command list, so
/// comparing it against the generated man pages keeps the assertion in step
/// with the tree without a second handwritten schema.
fn subcommands() -> Vec<String> {
    let help = run_success(&["--help"]);
    let stdout = String::from_utf8(help.stdout).expect("help is UTF-8");
    stdout
        .split("Commands:")
        .nth(1)
        .and_then(|section| section.split("Options:").next())
        .expect("help lists commands")
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| name != &"help")
        .map(str::to_owned)
        .collect()
}

#[test]
fn documentation_generates_completions_and_man_pages_for_every_command() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let directory = temporary.path().join("generated");
    let output = run_success(&["documentation", "--directory", path_text(&directory)]);
    assert!(
        output.stdout.is_empty(),
        "generation writes files, not output"
    );

    for file in [
        "packetcraftr.bash",
        "packetcraftr.elv",
        "packetcraftr.fish",
        "_packetcraftr",
        "_packetcraftr.ps1",
    ] {
        let path = directory.join("completions").join(file);
        assert!(
            path.is_file() && path.metadata().unwrap().len() > 0,
            "missing or empty completion {file}"
        );
    }
    let bash = std::fs::read_to_string(directory.join("completions/packetcraftr.bash"))
        .expect("bash completion");
    for option in ["--dissect", "--decode-as", "--field"] {
        assert!(
            bash.contains(option),
            "bash completion misses finalized option {option}"
        );
    }

    let man = directory.join("man");
    let root = man.join("packetcraftr.1");
    assert!(
        root.is_file() && root.metadata().unwrap().len() > 0,
        "missing root man page"
    );
    for subcommand in subcommands() {
        let page = man.join(format!("packetcraftr-{subcommand}.1"));
        assert!(
            page.is_file() && page.metadata().unwrap().len() > 0,
            "missing or empty man page for {subcommand}"
        );
    }
    // roff escapes hyphens as `\-`; normalize before checking option names.
    let capture = std::fs::read_to_string(man.join("packetcraftr-capture.1"))
        .expect("capture page")
        .replace("\\-", "-");
    assert!(
        capture.contains("--dissect") && capture.contains("--decode-as"),
        "capture man page misses finalized options"
    );
}

#[test]
fn documentation_reports_an_io_failure_for_an_unwritable_directory() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let occupied = temporary.path().join("occupied");
    std::fs::write(&occupied, b"file").expect("occupying file");

    let output = run(&["documentation", "--directory", path_text(&occupied)]);
    assert_eq!(output.status.code(), Some(5));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("io.documentation"),
        "stderr should carry the classification: {stderr}"
    );
}
