use crate::rules::model::{PacketContext, RuleLogLevel};
use log::{debug, error, info, trace, warn};
use std::borrow::Cow;

pub fn log_message(level: RuleLogLevel, rule_name: &str, message: &str) {
    match level {
        RuleLogLevel::Trace => trace!("rule '{}': {}", rule_name, message),
        RuleLogLevel::Debug => debug!("rule '{}': {}", rule_name, message),
        RuleLogLevel::Info => info!("rule '{}': {}", rule_name, message),
        RuleLogLevel::Warn => warn!("rule '{}': {}", rule_name, message),
        RuleLogLevel::Error => error!("rule '{}': {}", rule_name, message),
    }
}

pub fn apply_template(template: &str, packet: Option<&PacketContext>) -> String {
    let mut result = String::with_capacity(template.len() + 128);
    let mut cursor = 0;

    while let Some(start) = template[cursor..].find('{') {
        let match_index = cursor + start;
        result.push_str(&template[cursor..match_index]);

        let remainder = &template[match_index..];

        if remainder.starts_with("{description}") {
            match packet {
                Some(ctx) => result.push_str(&sanitize_input(&ctx.description)),
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{description}".len();
        } else if remainder.starts_with("{source}") {
            match packet.and_then(|ctx| ctx.source.as_deref()) {
                Some(s) => result.push_str(&sanitize_input(s)),
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{source}".len();
        } else if remainder.starts_with("{destination}") {
            match packet.and_then(|ctx| ctx.destination.as_deref()) {
                Some(s) => result.push_str(&sanitize_input(s)),
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{destination}".len();
        } else if remainder.starts_with("{length}") {
            match packet {
                Some(ctx) => {
                    use std::fmt::Write;
                    let _ = write!(result, "{}", ctx.length);
                }
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{length}".len();
        } else if remainder.starts_with("{timestamp}") {
            match packet {
                Some(ctx) => {
                    use std::fmt::Write;
                    let _ = write!(result, "{}", humantime::format_rfc3339(ctx.timestamp));
                }
                None => result.push_str("<unknown>"),
            }
            cursor = match_index + "{timestamp}".len();
        } else {
            result.push('{');
            cursor = match_index + 1;
        }
    }

    result.push_str(&template[cursor..]);
    result
}

fn sanitize_input(input: &str) -> Cow<'_, str> {
    // Retain only non-control characters to prevent log injection (e.g. newlines)
    // and argument confusion.
    if input.chars().any(|c| c.is_control()) {
        Cow::Owned(input.chars().filter(|c| !c.is_control()).collect())
    } else {
        Cow::Borrowed(input)
    }
}

pub fn render_option(field: &mut Option<String>, packet: Option<&PacketContext>) {
    if let Some(value) = field.as_mut() {
        let rendered = apply_template(value, packet);
        *value = rendered;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::SystemTime;

    #[test]
    fn sanitize_input_removes_control_chars() {
        let input = "hello\nworld\r\t";
        let sanitized = sanitize_input(input);
        assert_eq!(sanitized, "helloworld");
    }

    #[test]
    fn apply_template_without_packet_uses_unknown_placeholders() {
        let rendered = apply_template(
            "src={source} dst={destination} len={length} desc={description} ts={timestamp}",
            None,
        );

        assert_eq!(
            rendered,
            "src=<unknown> dst=<unknown> len=<unknown> desc=<unknown> ts=<unknown>"
        );
    }

    #[test]
    fn apply_template_with_context_replaces_placeholders() {
        let ctx = PacketContext {
            description: "test packet".to_string(),
            source: Some("192.168.1.1".to_string()),
            destination: Some("192.168.1.2".to_string()),
            length: 100,
            timestamp: SystemTime::now(),
        };

        let result = apply_template("from {source} to {destination}", Some(&ctx));
        assert_eq!(result, "from 192.168.1.1 to 192.168.1.2");

        let result2 = apply_template("desc: {description} len: {length}", Some(&ctx));
        assert_eq!(result2, "desc: test packet len: 100");
    }

    #[test]
    fn packet_context_with_missing_source() {
        let ctx = PacketContext {
            description: "test".to_string(),
            source: None,
            destination: Some("192.168.1.1".to_string()),
            length: 50,
            timestamp: SystemTime::now(),
        };

        let result = apply_template("{source}", Some(&ctx));
        assert_eq!(result, "<unknown>");
    }

    #[test]
    fn packet_context_with_missing_destination() {
        let ctx = PacketContext {
            description: "test".to_string(),
            source: Some("192.168.1.1".to_string()),
            destination: None,
            length: 50,
            timestamp: SystemTime::now(),
        };

        let result = apply_template("{destination}", Some(&ctx));
        assert_eq!(result, "<unknown>");
    }

    #[test]
    fn render_option_replaces_template_when_some() {
        let ctx = PacketContext {
            description: "test".to_string(),
            source: Some("192.168.1.1".to_string()),
            destination: Some("192.168.1.2".to_string()),
            length: 100,
            timestamp: SystemTime::now(),
        };

        let mut field = Some("{source}".to_string());
        render_option(&mut field, Some(&ctx));
        assert_eq!(field, Some("192.168.1.1".to_string()));
    }

    #[test]
    fn render_option_leaves_none_unchanged() {
        let ctx = PacketContext {
            description: "test".to_string(),
            source: Some("192.168.1.1".to_string()),
            destination: Some("192.168.1.2".to_string()),
            length: 100,
            timestamp: SystemTime::now(),
        };

        let mut field: Option<String> = None;
        render_option(&mut field, Some(&ctx));
        assert_eq!(field, None);
    }

    #[test]
    fn apply_template_handles_timestamp() {
        let ctx = PacketContext {
            description: "test".to_string(),
            source: Some("192.168.1.1".to_string()),
            destination: Some("192.168.1.2".to_string()),
            length: 100,
            timestamp: SystemTime::now(),
        };

        let result = apply_template("time: {timestamp}", Some(&ctx));
        assert!(result.starts_with("time: "));
        // timestamp should be in RFC3339 format, which contains 'T'
        assert!(result.contains('T'));
    }

    #[test]
    fn apply_template_multiple_placeholders() {
        let ctx = PacketContext {
            description: "icmp echo".to_string(),
            source: Some("10.0.0.1".to_string()),
            destination: Some("10.0.0.2".to_string()),
            length: 64,
            timestamp: SystemTime::now(),
        };

        let result = apply_template(
            "{description} from {source} to {destination} ({length} bytes)",
            Some(&ctx),
        );
        assert_eq!(result, "icmp echo from 10.0.0.1 to 10.0.0.2 (64 bytes)");
    }

    #[test]
    fn apply_template_no_placeholders() {
        let ctx = PacketContext {
            description: "test".to_string(),
            source: Some("192.168.1.1".to_string()),
            destination: Some("192.168.1.2".to_string()),
            length: 100,
            timestamp: SystemTime::now(),
        };

        let result = apply_template("no placeholders here", Some(&ctx));
        assert_eq!(result, "no placeholders here");
    }

    #[test]
    fn apply_template_with_all_unknown() {
        let result = apply_template(
            "{source} {destination} {description} {length} {timestamp}",
            None,
        );
        assert!(result.contains("<unknown>"));
        assert_eq!(result.split("<unknown>").count(), 6); // 5 placeholders + 1 = 6 parts
    }

    #[test]
    fn render_option_with_no_context() {
        let mut field = Some("{source}".to_string());
        render_option(&mut field, None);
        assert_eq!(field, Some("<unknown>".to_string()));
    }

    #[test]
    fn template_injection_control_chars() {
        let ctx = PacketContext {
            description: "malicious\nentry".to_string(),
            source: Some("1.2.3.4\r".to_string()),
            destination: Some("5.6.7.8".to_string()),
            length: 100,
            timestamp: SystemTime::now(),
        };

        let template = "Log: {description} from {source}";
        let result = apply_template(template, Some(&ctx));

        // Expect sanitized output (newlines and carriage returns removed)
        assert_eq!(result, "Log: maliciousentry from 1.2.3.4");
    }

    use proptest::prelude::*;

    fn expected_optional_text(value: Option<&str>) -> String {
        value
            .map(|value| sanitize_input(value).into_owned())
            .unwrap_or_else(|| "<unknown>".to_string())
    }

    fn expected_placeholder_value(placeholder: &str, packet: &PacketContext) -> String {
        match placeholder {
            "{source}" => expected_optional_text(packet.source.as_deref()),
            "{destination}" => expected_optional_text(packet.destination.as_deref()),
            "{description}" => sanitize_input(&packet.description).into_owned(),
            "{length}" => packet.length.to_string(),
            "{timestamp}" => humantime::format_rfc3339(packet.timestamp).to_string(),
            _ => unreachable!("test helper only supports known placeholders"),
        }
    }

    prop_compose! {
        fn packet_context_strategy()(
            description in any::<String>(),
            source in prop::option::of(any::<String>()),
            destination in prop::option::of(any::<String>()),
            length in any::<usize>()
        ) -> PacketContext {
            PacketContext {
                description,
                source,
                destination,
                length,
                timestamp: SystemTime::now(),
            }
        }
    }

    proptest! {
        #[test]
        fn fuzz_apply_template_substitution(
            packet in packet_context_strategy()
        ) {
            let template = "src={source} dst={destination}";
            let result = apply_template(template, Some(&packet));

            let expected = format!(
                "src={} dst={}",
                expected_optional_text(packet.source.as_deref()),
                expected_optional_text(packet.destination.as_deref())
            );

            prop_assert_eq!(result, expected);
        }

        #[test]
        fn fuzz_random_template_substitution(
            parts in prop::collection::vec(proptest::string::string_regex("[^{}]*").unwrap(), 1..10),
            packet in packet_context_strategy()
        ) {
             // Construct a template by interleaving random strings with placeholders
             let placeholders = ["{source}", "{destination}", "{description}", "{length}", "{timestamp}"];
             let mut template = String::new();
             let mut expected = String::new();
             for (i, part) in parts.iter().enumerate() {
                 let placeholder = placeholders[i % placeholders.len()];
                 template.push_str(part);
                 template.push_str(placeholder);
                 expected.push_str(part);
                 expected.push_str(&expected_placeholder_value(placeholder, &packet));
             }

             let result = apply_template(&template, Some(&packet));

             prop_assert_eq!(result, expected);
        }
    }
}
