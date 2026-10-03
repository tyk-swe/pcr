// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use packetcraftr_core::expression;
use packetcraftr_core::filter::{self, Filter};
use packetcraftr_core::layer::selector::Selector;
use packetcraftr_core::protocol::builtin;

use super::*;
use crate::command_options::TemplateArgs;
use crate::errors::KINDS;
use crate::input::apply_overrides;

/// Runs one embedded example through its parser, compiler, or strict packet builder.
fn check(kind: &str, source: &str) -> Result<(), String> {
    let registry = builtin::registry();
    let recipe = || {
        expression::parse(
            "ethernet()/ipv4(src=192.0.2.1,dst=192.0.2.2)/ipv4(src=198.51.100.1,dst=198.51.100.2)/udp()/raw()",
            &registry,
            expression::Limits::default(),
        )
        .expect("fixture recipe")
    };
    match kind {
        "expr" => {
            let packet = expression::parse(source, &registry, expression::Limits::default())
                .map_err(|error| error.to_string())?;
            packetcraftr_core::build::Builder::new(Arc::clone(&registry))
                .build(packet, Default::default(), Default::default())
                .map(drop)
                .map_err(|error| error.to_string())
        }
        "value" => expression::parse_value(source, expression::Limits::default())
            .map(drop)
            .map_err(|error| error.to_string()),
        "selector" => source
            .parse::<Selector>()
            .map(drop)
            .map_err(|error| error.to_string()),
        "set" => apply_overrides(&mut recipe(), &registry, &[source.to_owned()])
            .map_err(|error| error.message),
        "axis" => TemplateArgs {
            axes: vec![source.to_owned()],
            max_template_packets: 10_000,
        }
        .parse()
        .and_then(|axes| axes.into_template(recipe(), &registry))
        .map(drop)
        .map_err(|error| error.message),
        "filter" => Filter::compile(source, &registry, filter::Limits::default())
            .map(drop)
            .map_err(|error| error.to_string()),
        other => Err(format!("unknown example kind {other}")),
    }
}

fn examples(source: &str) -> Vec<(&str, &str)> {
    source.lines().filter_map(example).collect()
}

#[test]
fn every_embedded_example_is_accepted_by_its_real_parser() {
    let mut counts = BTreeMap::<&str, usize>::new();
    for topic in [text::EXPRESSIONS, text::FILTERS] {
        for (kind, source) in examples(topic) {
            check(kind, source).unwrap_or_else(|error| panic!("@{kind} {source}: {error}"));
            *counts.entry(kind).or_default() += 1;
        }
    }
    // A topic that lost its examples would otherwise pass vacuously.
    for (kind, minimum) in [
        ("expr", 4),
        ("value", 12),
        ("selector", 3),
        ("set", 3),
        ("axis", 2),
        ("filter", 25),
    ] {
        assert!(
            counts.get(kind).copied().unwrap_or(0) >= minimum,
            "{kind}: {counts:?}"
        );
    }
}

#[test]
fn a_broken_example_fails_the_drift_check() {
    for (kind, source) in [
        ("expr", "ipv4(nosuchfield=1)"),
        ("expr", "nosuchprotocol()"),
        ("expr", "ipv6()/udp(dport=5353)/raw(text=ping)"),
        ("value", "hex(\"0\")"),
        ("selector", "ipv4"),
        ("set", "ipv4#9.ttl=5"),
        ("axis", "ipv4.ttl=9..1"),
        ("filter", "tcp.flags &&& 1"),
        ("filter", "ip.src contains"),
        ("filter", "nosuchprotocol.field == 1"),
        ("unknown", "x"),
    ] {
        assert!(check(kind, source).is_err(), "@{kind} {source}");
    }
}

#[test]
fn the_filter_topic_exercises_every_operator_and_form_it_documents() {
    let sources = examples(text::FILTERS)
        .into_iter()
        .map(|(_, source)| source)
        .collect::<Vec<_>>();
    for needle in [
        " contains ",
        " startswith ",
        " endswith ",
        " icontains ",
        " iequals ",
        " & ",
        "..",
        " in {",
        " in 192.0.2.0/24",
        "len(",
        "count(",
        "[*]",
        "[-1]",
        "#2",
        "#last",
        "[0:3]",
        "b\"",
        "frame.",
        "tcp.stream",
        "udp.stream",
    ] {
        assert!(
            sources.iter().any(|source| source.contains(needle)),
            "no filter example uses `{needle}`"
        );
    }
}

#[test]
fn topics_contain_only_documentation_addresses() {
    let documentation_v4 = |address: Ipv4Addr| {
        let [a, b, c, _] = address.octets();
        matches!((a, b, c), (192, 0, 2) | (198, 51, 100) | (127, ..))
    };
    for topic in TOPICS {
        let body = (topic.body)();
        for token in body.split(|character: char| !(character.is_ascii_digit() || character == '.'))
        {
            if let Ok(address) = token.trim_matches('.').parse::<Ipv4Addr>() {
                assert!(
                    documentation_v4(address),
                    "{}: {address} is not a documentation address",
                    topic.name
                );
            }
        }
        for token in body.split(|character: char| {
            !(character.is_ascii_hexdigit() || character == ':' || character == '.')
        }) {
            if !token.contains("::") {
                continue;
            }
            let token = token.trim_matches(|character| character == ':' || character == '.');
            if let Ok(address) = token.parse::<Ipv6Addr>() {
                assert!(
                    address.segments()[..2] == [0x2001, 0x0db8] || address.is_loopback(),
                    "{}: {address} is not a documentation address",
                    topic.name
                );
            }
        }
    }
}

#[test]
fn the_listing_names_every_topic_and_unknown_names_list_them() {
    let listing = render(None).expect("listing");
    for name in ["expressions", "filters", "formats", "exit-codes"] {
        assert!(listing.contains(name), "{listing}");
    }

    let error = render(Some("nope")).expect_err("unknown topic");
    assert_eq!(error.exit_code(), 2);
    for name in names() {
        assert!(error.message.contains(name), "{}", error.message);
    }
    assert!(render(Some("FILTERS")).is_ok());
}

#[test]
fn printed_topics_show_examples_without_their_drift_tags() {
    for topic in TOPICS {
        let body = (topic.body)();
        assert!(!body.contains("  @"), "{}: {body}", topic.name);
    }
    assert!(
        render(Some("filters"))
            .unwrap()
            .contains("    ip.src in 192.0.2.0/24\n")
    );
}

#[test]
fn generated_topics_follow_the_command_and_error_tables() {
    let formats = render(Some("formats")).unwrap();
    for command in Command::ALL {
        for format in command.formats() {
            let line = formats
                .lines()
                .find(|line| line.trim_start().starts_with(command.as_str()))
                .unwrap_or_else(|| panic!("{} is listed", command.as_str()));
            assert!(line.contains(format.as_str()), "{line}");
        }
    }

    let codes = render(Some("exit-codes")).unwrap();
    for kind in KINDS {
        let code = crate::errors::exit_code_for(kind);
        assert!(
            codes
                .lines()
                .any(|line| line.trim_start().starts_with(&code.to_string())),
            "{codes}"
        );
    }
}

#[test]
fn only_text_output_is_offered() {
    let error = Args { name: None }
        .generate(Format::Json)
        .expect_err("machine output is refused");
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn the_filter_topic_names_exactly_the_commands_that_take_a_filter() {
    use clap::CommandFactory;

    let definition = crate::cli::Cli::command();
    let accepting = definition
        .get_subcommands()
        .filter(|command| {
            command
                .get_arguments()
                .any(|argument| argument.get_long() == Some("filter"))
        })
        .map(|command| command.get_name().to_owned())
        .collect::<BTreeSet<_>>();
    let sentence = text::FILTERS
        .split("accept it as `--filter`")
        .next()
        .expect("the sentence naming the commands");
    let named = sentence
        .split('`')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    assert_eq!(named, accepting);
}
