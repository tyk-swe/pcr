// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

// CLI error classification and exit-code mapping.

#[derive(Debug)]
struct CliError {
    exit_code: u8,
    message: String,
    classification: Classification,
    causes: Vec<String>,
    sequence: Option<u64>,
}

impl CliError {
    fn new(exit_code: u8, message: impl Into<String>) -> Self {
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

    fn classified(error: impl Classified + std::fmt::Display) -> Self {
        let classification = error.classification();
        let causes = error.causes();
        Self::from_classification(classification, error.to_string(), causes)
    }

    fn from_classification(
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

    fn at_sequence(mut self, sequence: u64) -> Self {
        self.sequence = Some(sequence);
        self
    }

    fn at_sequence_if_absent(mut self, sequence: u64) -> Self {
        self.sequence.get_or_insert(sequence);
        self
    }

    fn with_cleanup(mut self, cleanup: LiveIoError) -> Self {
        let operation = self.message.clone();
        self.message = format!("{operation}; capture shutdown also failed: {cleanup}");
        if self.causes.is_empty() {
            self.causes.push(operation);
        }
        self.causes.push(cleanup.to_string());
        self
    }

    fn output_error(&self) -> OutputError {
        OutputError::new(
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

fn machine_format_from_env() -> Option<OutputFormat> {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    machine_format(&arguments)
}

fn machine_format(arguments: &[std::ffi::OsString]) -> Option<OutputFormat> {
    arguments
        .iter()
        .take_while(|argument| argument.as_os_str() != "--")
        .enumerate()
        .find_map(|(index, argument)| {
            let value = if argument.as_os_str() == "--output" {
                arguments.get(index + 1).and_then(|value| value.to_str())
            } else {
                argument
                    .to_str()
                    .and_then(|argument| argument.strip_prefix("--output="))
            }?;
            match value {
                "json" => Some(OutputFormat::Json),
                "ndjson" => Some(OutputFormat::Ndjson),
                _ => None,
            }
        })
}

fn command_from_env() -> Option<CommandName> {
    const COMMANDS: &[(&str, CommandName)] = &[
        ("build", CommandName::Build),
        ("dissect", CommandName::Dissect),
        ("plan", CommandName::Plan),
        ("send", CommandName::Send),
        ("exchange", CommandName::Exchange),
        ("capture", CommandName::Capture),
        ("read", CommandName::Read),
        ("replay", CommandName::Replay),
        ("scan", CommandName::Scan),
        ("traceroute", CommandName::Traceroute),
        ("dns", CommandName::Dns),
        ("fuzz", CommandName::Fuzz),
        ("interfaces", CommandName::Interfaces),
        ("routes", CommandName::Routes),
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

fn exit_code(code: u8) -> ExitCode {
    ExitCode::from(code)
}
