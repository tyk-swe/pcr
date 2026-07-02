// Copyright (C) 2026 rkdxodud-tyk
// SPDX-License-Identifier: AGPL-3.0-only

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CommandCategory {
    Packet,
    Tool,
    Utility,
    Interactive,
}

impl CommandCategory {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Packet => "packet",
            Self::Tool => "tool",
            Self::Utility => "utility",
            Self::Interactive => "interactive",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct CommandMetadata {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub examples: &'static [&'static str],
    pub help_topics: &'static [&'static str],
    pub feature_gate: Option<&'static str>,
    pub category: CommandCategory,
}

pub(crate) const CLI_AFTER_HELP: &str = "EXAMPLES:

  1. Preview a UDP payload to loopback without transmitting:
     packetcraftr plan udp 127.0.0.1:9 --data hello

  2. Preview JSON output for automation:
     packetcraftr --output-format json plan udp 127.0.0.1:9 --data hello

  3. Build an ICMP Echo Request preview:
     packetcraftr plan icmp 127.0.0.1 --icmp-type 8 --icmp-code 0

  4. Query DNS:
     packetcraftr dns query example.com --type A --server 127.0.0.1";

pub(crate) const COMMANDS: &[CommandMetadata] = &[
    CommandMetadata {
        name: "send",
        aliases: &[],
        examples: &[
            "packetcraftr send tcp 127.0.0.1:443 --flags syn",
            "packetcraftr --dry-run send udp 127.0.0.1:9 --data hello",
        ],
        help_topics: &["send", "tcp", "udp", "icmp", "payload"],
        feature_gate: None,
        category: CommandCategory::Packet,
    },
    CommandMetadata {
        name: "plan",
        aliases: &["dry-run"],
        examples: &[
            "packetcraftr plan udp 127.0.0.1:9 --data hello",
            "packetcraftr dry-run -d 127.0.0.1 --data hello udp --dport 9",
        ],
        help_topics: &["plan", "dry-run"],
        feature_gate: None,
        category: CommandCategory::Packet,
    },
    CommandMetadata {
        name: "dns",
        aliases: &["dns-query"],
        examples: &[
            "packetcraftr dns query example.com --type A --server 127.0.0.1",
            "packetcraftr dns-query --domain example.com --type AAAA --server 127.0.0.1",
        ],
        help_topics: &["dns", "dns query", "dns-query"],
        feature_gate: None,
        category: CommandCategory::Tool,
    },
    CommandMetadata {
        name: "repl",
        aliases: &["interactive"],
        examples: &[
            "packetcraftr repl",
            "packetcraftr interactive --auto-listen",
        ],
        help_topics: &["repl", "interactive"],
        feature_gate: Some("repl"),
        category: CommandCategory::Interactive,
    },
    CommandMetadata {
        name: "trace",
        aliases: &["traceroute"],
        examples: &["packetcraftr trace --dest example.com"],
        help_topics: &["trace", "traceroute"],
        feature_gate: Some("traceroute"),
        category: CommandCategory::Tool,
    },
    CommandMetadata {
        name: "listen",
        aliases: &[],
        examples: &["packetcraftr listen --filter tcp --timeout 10"],
        help_topics: &["listen"],
        feature_gate: Some("pcap"),
        category: CommandCategory::Tool,
    },
    CommandMetadata {
        name: "scan",
        aliases: &[],
        examples: &["packetcraftr scan tcp-syn --target 192.0.2.1 --ports 80,443"],
        help_topics: &["scan"],
        feature_gate: Some("scan"),
        category: CommandCategory::Tool,
    },
    CommandMetadata {
        name: "doctor",
        aliases: &[],
        examples: &[
            "packetcraftr doctor",
            "packetcraftr doctor --json --target 192.168.1.1",
        ],
        help_topics: &["doctor"],
        feature_gate: None,
        category: CommandCategory::Utility,
    },
    CommandMetadata {
        name: "features",
        aliases: &[],
        examples: &["packetcraftr features", "packetcraftr features --json"],
        help_topics: &["features"],
        feature_gate: None,
        category: CommandCategory::Utility,
    },
    CommandMetadata {
        name: "examples",
        aliases: &[],
        examples: &[
            "packetcraftr examples",
            "packetcraftr examples send",
            "packetcraftr examples dns",
        ],
        help_topics: &["examples"],
        feature_gate: None,
        category: CommandCategory::Utility,
    },
    CommandMetadata {
        name: "completions",
        aliases: &[],
        examples: &[
            "packetcraftr completions bash",
            "packetcraftr completions zsh",
        ],
        help_topics: &["completions"],
        feature_gate: None,
        category: CommandCategory::Utility,
    },
    CommandMetadata {
        name: "man",
        aliases: &[],
        examples: &["packetcraftr man"],
        help_topics: &["man"],
        feature_gate: None,
        category: CommandCategory::Utility,
    },
];

pub(crate) fn command_catalog() -> &'static [CommandMetadata] {
    COMMANDS
}

pub(crate) fn find_command(topic: &str) -> Option<&'static CommandMetadata> {
    let normalized = topic.trim().to_ascii_lowercase();
    command_catalog().iter().find(|command| {
        command.name == normalized
            || command.aliases.iter().any(|alias| *alias == normalized)
            || command
                .help_topics
                .iter()
                .any(|help_topic| *help_topic == normalized)
    })
}

pub(crate) fn top_level_command_names() -> Vec<&'static str> {
    command_catalog()
        .iter()
        .flat_map(|command| std::iter::once(command.name).chain(command.aliases.iter().copied()))
        .collect()
}

pub(crate) fn render_examples(topic: Option<&str>) -> String {
    let commands: Vec<&CommandMetadata> = match topic {
        Some(topic) => find_command(topic).into_iter().collect(),
        None => command_catalog().iter().collect(),
    };

    if commands.is_empty() {
        let topic = topic.unwrap_or_default();
        return format!("No examples for '{topic}'.\n");
    }

    let mut output = String::new();
    if topic.is_none() {
        output.push_str("Commands: ");
        output.push_str(&top_level_command_names().join(", "));
        output.push_str("\n\n");
    }
    for command in commands {
        output.push_str(command.category.label());
        output.push(' ');
        output.push_str(command.name);
        output.push_str(" examples");
        if let Some(feature) = command.feature_gate {
            output.push_str(" [feature: ");
            output.push_str(feature);
            output.push(']');
        }
        output.push('\n');
        for example in command.examples {
            output.push_str("  ");
            output.push_str(example);
            output.push('\n');
        }
        output.push('\n');
    }
    output
}
