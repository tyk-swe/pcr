// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// CLI error classification and exit-code mapping.

use packetcraftr::{
    error::{Classification, Classified, Kind},
    net, output,
};

use super::arguments::CliColorChoice;

#[derive(Debug)]
pub(super) struct CliError {
    pub(super) exit_code: u8,
    pub(super) message: String,
    pub(super) classification: Classification,
    pub(super) causes: Vec<String>,
    pub(super) sequence: Option<u64>,
}

impl CliError {
    pub(super) fn new(exit_code: u8, message: impl Into<String>) -> Self {
        let kind = match exit_code {
            2 => Kind::Cli,
            3 => Kind::Packet,
            4 => Kind::Capability,
            5 => Kind::Io,
            6 => Kind::Policy,
            _ => Kind::Internal,
        };
        Self {
            exit_code,
            message: message.into(),
            classification: Classification::new(
                match kind {
                    Kind::Cli => "cli.error",
                    Kind::Packet => "packet.error",
                    Kind::Capability => "capability.unavailable",
                    Kind::Io => "io.runtime",
                    Kind::Policy => "policy.denied",
                    Kind::Internal => "internal.error",
                },
                kind,
                None,
            ),
            causes: Vec::new(),
            sequence: None,
        }
    }

    pub(super) fn classified(error: impl Classified + std::fmt::Display) -> Self {
        let classification = error.classification();
        let causes = error.causes();
        Self::from_classification(classification, error.to_string(), causes)
    }

    pub(super) fn classified_at_optional_sequence(
        error: impl Classified + std::fmt::Display,
        sequence: Option<u64>,
    ) -> Self {
        let mut error = Self::classified(error);
        error.sequence = sequence;
        error
    }

    pub(super) fn from_classification(
        classification: Classification,
        message: impl Into<String>,
        causes: Vec<String>,
    ) -> Self {
        Self {
            exit_code: exit_code_for_kind(classification.kind),
            message: message.into(),
            classification,
            causes,
            sequence: None,
        }
    }

    pub(super) fn at_sequence(mut self, sequence: u64) -> Self {
        self.sequence = Some(sequence);
        self
    }

    pub(super) fn at_sequence_if_absent(mut self, sequence: u64) -> Self {
        self.sequence.get_or_insert(sequence);
        self
    }

    pub(super) fn into_boundary_error(self) -> packetcraftr::workflow::BoundaryError {
        packetcraftr::workflow::BoundaryError::new(self.message, self.classification, self.causes)
    }

    pub(super) fn with_cleanup(mut self, cleanup: net::Error) -> Self {
        let operation = self.message.clone();
        self.message = format!("{operation}; capture shutdown also failed: {cleanup}");
        if self.causes.is_empty() {
            self.causes.push(operation);
        }
        self.causes.push(cleanup.to_string());
        self
    }

    pub(super) fn output_error(&self) -> output::envelope::Error {
        output::envelope::Error::new(
            self.classification,
            self.message.clone(),
            self.causes.clone(),
        )
    }
}

const fn exit_code_for_kind(kind: Kind) -> u8 {
    match kind {
        Kind::Cli => 2,
        Kind::Packet => 3,
        Kind::Capability => 4,
        Kind::Io => 5,
        Kind::Policy => 6,
        Kind::Internal => 70,
    }
}

pub(super) fn machine_format_from_env() -> Option<output::contract::Format> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    match option_value_before_end_of_options(&arguments, "--output")? {
        "json" => Some(output::contract::Format::Json),
        "ndjson" => Some(output::contract::Format::Ndjson),
        _ => None,
    }
}

pub(super) fn color_choice_from_env() -> CliColorChoice {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    match option_value_before_end_of_options(&arguments, "--color") {
        Some("always") => CliColorChoice::Always,
        Some("never") => CliColorChoice::Never,
        _ => CliColorChoice::Auto,
    }
}

fn option_value_before_end_of_options<'a>(
    arguments: &'a [std::ffi::OsString],
    option: &str,
) -> Option<&'a str> {
    let end = arguments
        .iter()
        .position(|argument| argument.as_os_str() == "--")
        .unwrap_or(arguments.len());
    let inline_prefix = format!("{option}=");
    for (index, argument) in arguments[..end].iter().enumerate() {
        if argument.as_os_str() == option {
            return arguments[..end]
                .get(index + 1)
                .and_then(|value| value.to_str());
        }
        if let Some(value) = argument
            .to_str()
            .and_then(|argument| argument.strip_prefix(&inline_prefix))
        {
            return Some(value);
        }
    }
    None
}

pub(super) fn command_from_env() -> Option<output::contract::Command> {
    const COMMANDS: &[(&str, output::contract::Command)] = &[
        ("build", output::contract::Command::Build),
        ("dissect", output::contract::Command::Dissect),
        ("plan", output::contract::Command::Plan),
        ("send", output::contract::Command::Send),
        ("exchange", output::contract::Command::Exchange),
        ("capture", output::contract::Command::Capture),
        ("read", output::contract::Command::Read),
        ("replay", output::contract::Command::Replay),
        ("scan", output::contract::Command::Scan),
        ("traceroute", output::contract::Command::Traceroute),
        ("dns", output::contract::Command::Dns),
        ("fuzz", output::contract::Command::Fuzz),
        ("interfaces", output::contract::Command::Interfaces),
        ("routes", output::contract::Command::Routes),
    ];
    std::env::args_os()
        .take_while(|argument| argument.as_os_str() != "--")
        .find_map(|argument| {
            let argument = argument.to_str()?;
            COMMANDS
                .iter()
                .find_map(|(name, command)| (*name == argument).then_some(*command))
        })
}
