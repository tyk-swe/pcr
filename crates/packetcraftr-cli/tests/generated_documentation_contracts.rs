// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

mod common;

use common::{path_text, run, run_success};

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
    let cause = stderr
        .lines()
        .find_map(|line| line.strip_prefix("caused by: "))
        .unwrap_or_else(|| panic!("stderr should carry the I/O cause: {stderr}"));
    assert_eq!(
        stderr.matches(cause).count(),
        1,
        "the I/O error appears only as the cause: {stderr}"
    );
}

#[cfg(packetcraftr_test_dev_full)]
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

#[test]
fn topics_list_and_print_built_in_references_as_text() {
    let listing = String::from_utf8(run_success(&["topics"]).stdout).unwrap();
    for name in ["expressions", "filters", "formats", "exit-codes"] {
        assert!(listing.contains(name), "{listing}");
    }

    let filters = String::from_utf8(run_success(&["topics", "filters"]).stdout).unwrap();
    for operator in ["contains", "startswith", "endswith", "icontains", "iequals"] {
        assert!(filters.contains(operator), "{operator}");
    }
    let expressions = String::from_utf8(run_success(&["topics", "expressions"]).stdout).unwrap();
    assert!(expressions.contains("repeat(BYTE,COUNT)"));
    let formats = String::from_utf8(run_success(&["topics", "formats"]).stdout).unwrap();
    assert!(formats.contains("build") && formats.contains("pcapng"));
    let codes = String::from_utf8(run_success(&["topics", "exit-codes"]).stdout).unwrap();
    assert!(codes.contains("130 cancelled"));

    let unknown = run(&["topics", "nope"]);
    assert_eq!(unknown.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&unknown.stderr);
    for name in ["expressions", "filters", "formats", "exit-codes"] {
        assert!(stderr.contains(name), "{stderr}");
    }
    let machine = run(&["--output", "json", "topics", "filters"]);
    assert_eq!(machine.status.code(), Some(2));
}

#[test]
fn topics_stay_outside_the_published_command_contract() {
    let schema = serde_json::to_string(common::output_schema()).unwrap();
    assert!(!schema.contains("\"topics\""));
    assert!(
        packetcraftr_cli::output::contract::Command::ALL
            .iter()
            .all(|command| command.as_str() != "topics")
    );
}

#[test]
fn build_read_and_dissect_help_point_at_the_filter_topic() {
    for command in ["build", "read", "dissect"] {
        let help = String::from_utf8(run_success(&[command, "--help"]).stdout).unwrap();
        assert!(
            help.contains("See `packetcraftr topics filters`"),
            "{command}: {help}"
        );
    }
}
