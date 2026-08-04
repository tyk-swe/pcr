// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use clap::Args;
use packetcraftr::{capture, client, net};

#[derive(Clone, Debug, Args)]
struct PublicDestinationArgs {
    /// Authorize destinations classified as public: globally routable and multicast addresses.
    #[arg(long)]
    allow_public_destinations: bool,
}

#[derive(Clone, Debug, Args)]
struct HostnameResolutionArgs {
    /// Authorize hostname resolution before route lookup.
    #[arg(long)]
    allow_hostname_resolution: bool,
    /// Maximum distinct addresses accepted from one hostname resolution.
    #[arg(long, default_value_t = client::policy::DEFAULT_MAX_RESOLVED_ADDRESSES)]
    max_resolved_addresses: usize,
}

#[derive(Clone, Debug, Args)]
struct PermissivePacketArgs {
    /// Policy-level opt-in for permissive or malformed live packets.
    #[arg(long)]
    allow_permissive_packets: bool,
}

#[derive(Clone, Debug, Args)]
struct TrafficBudgetArgs {
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = 10_000)]
    max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = net::capture::Limits::default().max_bytes as u64)]
    max_bytes: u64,
}

#[derive(Clone, Debug, Args)]
struct ReplayTrafficBudgetArgs {
    /// Maximum packets authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_FRAMES)]
    max_packets: u64,
    /// Maximum wire bytes authorized for one operation.
    #[arg(long, default_value_t = capture::DEFAULT_STREAM_BYTES)]
    max_bytes: u64,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct PlanPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct SendPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct HostnameTrafficPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    hostname_resolution: HostnameResolutionArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct ReplayPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    budgets: ReplayTrafficBudgetArgs,
}

#[derive(Clone, Debug, Args)]
pub(crate) struct FuzzPolicyArgs {
    #[command(flatten)]
    public_destination: PublicDestinationArgs,
    #[command(flatten)]
    permissive_packet: PermissivePacketArgs,
    #[command(flatten)]
    budgets: TrafficBudgetArgs,
}

impl PublicDestinationArgs {
    fn apply_to(self, policy: &mut client::policy::Policy) {
        policy.allow_public_destinations = self.allow_public_destinations;
    }
}

impl HostnameResolutionArgs {
    fn apply_to(self, policy: &mut client::policy::Policy) {
        policy.allow_hostname_resolution = self.allow_hostname_resolution;
        policy.max_resolved_addresses = self.max_resolved_addresses;
    }
}

impl PermissivePacketArgs {
    fn apply_to(self, policy: &mut client::policy::Policy) {
        policy.allow_permissive_packets = self.allow_permissive_packets;
    }
}

impl TrafficBudgetArgs {
    fn apply_to(self, policy: &mut client::policy::Policy) {
        policy.max_packets_per_operation = self.max_packets;
        policy.max_bytes_per_operation = self.max_bytes;
    }
}

impl ReplayTrafficBudgetArgs {
    fn apply_to(self, policy: &mut client::policy::Policy) {
        policy.max_packets_per_operation = self.max_packets;
        policy.max_bytes_per_operation = self.max_bytes;
    }
}

impl PlanPolicyArgs {
    pub(crate) fn into_policy(self) -> client::policy::Policy {
        let mut policy = client::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        policy
    }
}

impl SendPolicyArgs {
    pub(crate) fn into_policy(self) -> client::policy::Policy {
        let mut policy = client::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

impl HostnameTrafficPolicyArgs {
    pub(crate) fn into_policy(self) -> client::policy::Policy {
        let mut policy = client::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.hostname_resolution.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

impl ReplayPolicyArgs {
    pub(crate) fn into_policy(self) -> client::policy::Policy {
        let mut policy = client::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

impl FuzzPolicyArgs {
    pub(crate) fn into_policy(self) -> client::policy::Policy {
        let mut policy = client::policy::Policy::default();
        self.public_destination.apply_to(&mut policy);
        self.permissive_packet.apply_to(&mut policy);
        self.budgets.apply_to(&mut policy);
        policy
    }
}

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser, error::ErrorKind};
    use packetcraftr::{capture, client, net};

    use crate::arguments::{Cli, Command};

    const POLICY_OPTIONS: [&str; 6] = [
        "allow-public-destinations",
        "allow-hostname-resolution",
        "allow-permissive-packets",
        "max-packets",
        "max-bytes",
        "max-resolved-addresses",
    ];

    fn policy_for(arguments: &[&str]) -> client::policy::Policy {
        match Cli::try_parse_from(arguments).unwrap().command {
            Command::Plan(arguments) => arguments.policy.into_policy(),
            Command::Send(arguments) => arguments.policy.into_policy(),
            Command::Exchange(arguments) => arguments.send.policy.into_policy(),
            Command::Capture(arguments) => arguments.policy.into_policy(),
            Command::Replay(arguments) => arguments.policy.into_policy(),
            Command::Scan(arguments) => arguments.policy.into_policy(),
            Command::Traceroute(arguments) => arguments.policy.into_policy(),
            Command::Dns(arguments) => arguments.policy.into_policy(),
            Command::Fuzz(arguments) => arguments.policy.into_policy(),
            command => panic!("{} has no traffic policy", command.name().as_str()),
        }
    }

    fn command_arguments(command_name: &str) -> Vec<&str> {
        match command_name {
            "plan" | "send" | "exchange" | "capture" => {
                vec!["packetcraftr", command_name, "--packet", "raw()"]
            }
            "replay" => vec![
                "packetcraftr",
                "replay",
                "capture.pcap",
                "--interface",
                "test0",
            ],
            "scan" => vec!["packetcraftr", "scan", "192.0.2.1", "--ports", "80"],
            "traceroute" => vec!["packetcraftr", "traceroute", "192.0.2.1"],
            "dns" => vec!["packetcraftr", "dns", "192.0.2.53", "example.test"],
            "fuzz" => vec!["packetcraftr", "fuzz", "--packet", "raw()"],
            _ => panic!("missing test arguments for {command_name}"),
        }
    }

    fn assert_authorization_closed(policy: &client::policy::Policy) {
        assert!(!policy.allow_public_destinations);
        assert!(!policy.allow_hostname_resolution);
        assert!(!policy.allow_permissive_packets);
    }

    #[test]
    fn traffic_policy_options_have_the_exact_command_matrix() {
        let expected = [
            (
                "plan",
                vec![
                    "allow-public-destinations",
                    "allow-hostname-resolution",
                    "max-resolved-addresses",
                ],
            ),
            ("send", POLICY_OPTIONS.to_vec()),
            ("exchange", POLICY_OPTIONS.to_vec()),
            (
                "capture",
                vec![
                    "allow-public-destinations",
                    "allow-hostname-resolution",
                    "max-packets",
                    "max-bytes",
                    "max-resolved-addresses",
                ],
            ),
            (
                "replay",
                vec![
                    "allow-public-destinations",
                    "allow-permissive-packets",
                    "max-packets",
                    "max-bytes",
                ],
            ),
            (
                "scan",
                vec![
                    "allow-public-destinations",
                    "allow-hostname-resolution",
                    "max-packets",
                    "max-bytes",
                    "max-resolved-addresses",
                ],
            ),
            (
                "traceroute",
                vec![
                    "allow-public-destinations",
                    "allow-hostname-resolution",
                    "max-packets",
                    "max-bytes",
                    "max-resolved-addresses",
                ],
            ),
            (
                "dns",
                vec![
                    "allow-public-destinations",
                    "allow-hostname-resolution",
                    "max-packets",
                    "max-bytes",
                    "max-resolved-addresses",
                ],
            ),
            (
                "fuzz",
                vec![
                    "allow-public-destinations",
                    "allow-permissive-packets",
                    "max-packets",
                    "max-bytes",
                ],
            ),
        ];
        let command = Cli::command();
        for (name, expected_options) in expected {
            let subcommand = command
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("missing {name} command"));
            for option in POLICY_OPTIONS {
                let count = subcommand
                    .get_arguments()
                    .filter(|argument| argument.get_long() == Some(option))
                    .count();
                assert_eq!(
                    count,
                    usize::from(expected_options.contains(&option)),
                    "unexpected --{option} count on {name}"
                );
            }
        }

        for name in ["build", "dissect", "read", "expert", "follow", "stats"] {
            let subcommand = command
                .find_subcommand(name)
                .unwrap_or_else(|| panic!("missing {name} command"));
            for option in POLICY_OPTIONS {
                let expected_count = usize::from(
                    option == "max-bytes" && matches!(name, "read" | "expert" | "follow" | "stats"),
                );
                assert_eq!(
                    subcommand
                        .get_arguments()
                        .filter(|argument| argument.get_long() == Some(option))
                        .count(),
                    expected_count,
                    "offline {name} unexpectedly exposes --{option}"
                );
            }
            if matches!(name, "read" | "expert" | "follow" | "stats") {
                let max_bytes = subcommand
                    .get_arguments()
                    .find(|argument| argument.get_long() == Some("max-bytes"))
                    .unwrap();
                assert!(
                    max_bytes
                        .get_help()
                        .is_some_and(|help| help.to_string().contains("captured payload bytes")),
                    "offline {name} --max-bytes changed into a traffic-policy option"
                );
            }
        }
    }

    #[test]
    fn every_applicable_traffic_policy_option_parses() {
        let cases = [
            (
                "plan",
                vec![
                    "--allow-public-destinations",
                    "--allow-hostname-resolution",
                    "--max-resolved-addresses",
                    "7",
                ],
            ),
            (
                "send",
                vec![
                    "--allow-public-destinations",
                    "--allow-hostname-resolution",
                    "--allow-permissive-packets",
                    "--max-packets",
                    "11",
                    "--max-bytes",
                    "12",
                    "--max-resolved-addresses",
                    "7",
                ],
            ),
            (
                "exchange",
                vec![
                    "--allow-public-destinations",
                    "--allow-hostname-resolution",
                    "--allow-permissive-packets",
                    "--max-packets",
                    "11",
                    "--max-bytes",
                    "12",
                    "--max-resolved-addresses",
                    "7",
                ],
            ),
            (
                "capture",
                vec![
                    "--allow-public-destinations",
                    "--allow-hostname-resolution",
                    "--max-packets",
                    "11",
                    "--max-bytes",
                    "12",
                    "--max-resolved-addresses",
                    "7",
                ],
            ),
            (
                "replay",
                vec![
                    "--allow-public-destinations",
                    "--allow-permissive-packets",
                    "--max-packets",
                    "11",
                    "--max-bytes",
                    "12",
                ],
            ),
            (
                "scan",
                vec![
                    "--allow-public-destinations",
                    "--allow-hostname-resolution",
                    "--max-packets",
                    "11",
                    "--max-bytes",
                    "12",
                    "--max-resolved-addresses",
                    "7",
                ],
            ),
            (
                "traceroute",
                vec![
                    "--allow-public-destinations",
                    "--allow-hostname-resolution",
                    "--max-packets",
                    "11",
                    "--max-bytes",
                    "12",
                    "--max-resolved-addresses",
                    "7",
                ],
            ),
            (
                "dns",
                vec![
                    "--allow-public-destinations",
                    "--allow-hostname-resolution",
                    "--max-packets",
                    "11",
                    "--max-bytes",
                    "12",
                    "--max-resolved-addresses",
                    "7",
                ],
            ),
            (
                "fuzz",
                vec![
                    "--allow-public-destinations",
                    "--allow-permissive-packets",
                    "--max-packets",
                    "11",
                    "--max-bytes",
                    "12",
                ],
            ),
        ];

        for (command, options) in cases {
            let mut arguments = command_arguments(command);
            arguments.extend(options);
            Cli::try_parse_from(arguments)
                .unwrap_or_else(|error| panic!("{command} policy options failed: {error}"));
        }
    }

    #[test]
    fn removed_no_op_policy_options_are_unknown_arguments() {
        for (command, option) in [
            ("plan", "--allow-permissive-packets"),
            ("plan", "--max-packets"),
            ("capture", "--allow-permissive-packets"),
            ("scan", "--allow-permissive-packets"),
            ("traceroute", "--allow-permissive-packets"),
            ("dns", "--allow-permissive-packets"),
            ("fuzz", "--allow-hostname-resolution"),
            ("fuzz", "--max-resolved-addresses"),
            ("replay", "--allow-hostname-resolution"),
        ] {
            let mut arguments = command_arguments(command);
            arguments.push(option);
            if option == "--max-packets" || option == "--max-resolved-addresses" {
                arguments.push("1");
            }
            let error = Cli::try_parse_from(arguments).unwrap_err();
            assert_eq!(
                error.kind(),
                ErrorKind::UnknownArgument,
                "{command} {option}"
            );
        }
    }

    #[test]
    fn default_policy_parsing_keeps_every_authorization_gate_closed() {
        for command in [
            "plan",
            "send",
            "exchange",
            "capture",
            "replay",
            "scan",
            "traceroute",
            "dns",
            "fuzz",
        ] {
            let policy = policy_for(&command_arguments(command));
            assert_authorization_closed(&policy);
        }
    }

    #[test]
    fn operation_policy_conversions_map_only_their_applicable_groups() {
        let defaults = client::policy::Policy::default();
        let normal_bytes = u64::try_from(net::capture::Limits::default().max_bytes).unwrap();

        let plan = policy_for(&[
            "packetcraftr",
            "plan",
            "--packet",
            "raw()",
            "--allow-public-destinations",
            "--allow-hostname-resolution",
            "--max-resolved-addresses",
            "7",
        ]);
        assert!(plan.allow_public_destinations);
        assert!(plan.allow_hostname_resolution);
        assert!(!plan.allow_permissive_packets);
        assert_eq!(plan.max_resolved_addresses, 7);
        assert_eq!(
            plan.max_packets_per_operation,
            defaults.max_packets_per_operation
        );
        assert_eq!(
            plan.max_bytes_per_operation,
            defaults.max_bytes_per_operation
        );

        for command in ["send", "exchange"] {
            let mut arguments = command_arguments(command);
            arguments.extend([
                "--allow-public-destinations",
                "--allow-hostname-resolution",
                "--allow-permissive-packets",
                "--max-packets",
                "11",
                "--max-bytes",
                "12",
                "--max-resolved-addresses",
                "7",
            ]);
            let policy = policy_for(&arguments);
            assert!(policy.allow_public_destinations);
            assert!(policy.allow_hostname_resolution);
            assert!(policy.allow_permissive_packets);
            assert_eq!(policy.max_packets_per_operation, 11);
            assert_eq!(policy.max_bytes_per_operation, 12);
            assert_eq!(policy.max_resolved_addresses, 7);
        }

        for command in ["capture", "scan", "traceroute", "dns"] {
            let mut arguments = command_arguments(command);
            arguments.extend([
                "--allow-public-destinations",
                "--allow-hostname-resolution",
                "--max-packets",
                "11",
                "--max-bytes",
                "12",
                "--max-resolved-addresses",
                "7",
            ]);
            let policy = policy_for(&arguments);
            assert!(policy.allow_public_destinations);
            assert!(policy.allow_hostname_resolution);
            assert!(!policy.allow_permissive_packets);
            assert_eq!(policy.max_packets_per_operation, 11);
            assert_eq!(policy.max_bytes_per_operation, 12);
            assert_eq!(policy.max_resolved_addresses, 7);
        }

        for command in ["replay", "fuzz"] {
            let mut arguments = command_arguments(command);
            arguments.extend([
                "--allow-public-destinations",
                "--allow-permissive-packets",
                "--max-packets",
                "11",
                "--max-bytes",
                "12",
            ]);
            let policy = policy_for(&arguments);
            assert!(policy.allow_public_destinations);
            assert!(!policy.allow_hostname_resolution);
            assert!(policy.allow_permissive_packets);
            assert_eq!(policy.max_packets_per_operation, 11);
            assert_eq!(policy.max_bytes_per_operation, 12);
            assert_eq!(
                policy.max_resolved_addresses,
                defaults.max_resolved_addresses
            );
        }

        for command in [
            "send",
            "exchange",
            "capture",
            "scan",
            "traceroute",
            "dns",
            "fuzz",
        ] {
            let policy = policy_for(&command_arguments(command));
            assert_eq!(policy.max_packets_per_operation, 10_000, "{command}");
            assert_eq!(policy.max_bytes_per_operation, normal_bytes, "{command}");
        }
        let replay = policy_for(&command_arguments("replay"));
        assert_eq!(
            replay.max_packets_per_operation,
            capture::DEFAULT_STREAM_FRAMES
        );
        assert_eq!(
            replay.max_bytes_per_operation,
            capture::DEFAULT_STREAM_BYTES
        );
        assert_eq!(
            replay.max_resolved_addresses,
            client::policy::DEFAULT_MAX_RESOLVED_ADDRESSES
        );
    }
}
