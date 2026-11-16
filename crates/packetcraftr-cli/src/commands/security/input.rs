// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::invalid;
use crate::commands::Command;
use crate::errors::CliError;
use packetcraftr_core::security::{Report, Source, input};
use sha2::{Digest, Sha256};
use std::path::Path;

pub(in crate::commands) fn read(
    invocation: &crate::invocation::Invocation,
    path: &Path,
    limit: usize,
) -> Result<Vec<u8>, CliError> {
    crate::input::read_document(
        &invocation.control,
        path,
        limit,
        crate::input::InputKind::SecurityDocument,
    )
}

/// A pipe has one consumer; reject ambiguous inputs before consuming any bytes.
pub(in crate::commands) fn validate_stdin_sources<'a>(
    paths: impl IntoIterator<Item = &'a Path>,
) -> Result<(), CliError> {
    if paths
        .into_iter()
        .filter(|path| *path == Path::new("-"))
        .take(2)
        .count()
        > 1
    {
        return Err(invalid("only one input may read stdin (-) per command"));
    }
    Ok(())
}

pub(in crate::commands) fn source(path: &Path, bytes: &[u8]) -> Source {
    Source {
        path: path.display().to_string(),
        sha256: crate::output::hex::compact_hex(&Sha256::digest(bytes)),
    }
}

/// Validate the published envelope before admitting an assessment's input report.
pub(in crate::commands) fn report(bytes: &[u8]) -> Result<Report, CliError> {
    let security_commands = [
        Command::Hunt.as_str(),
        Command::DnsAnomalies.as_str(),
        Command::Beacons.as_str(),
        Command::AuditTls.as_str(),
        Command::AuditHttp.as_str(),
        Command::ScanDiff.as_str(),
    ];
    let engagement_commands = [
        Command::Scan.as_str(),
        Command::Differential.as_str(),
        Command::Fuzz.as_str(),
        Command::Exchange.as_str(),
        Command::Traceroute.as_str(),
    ];
    let allowed: Vec<&str> = security_commands
        .iter()
        .chain(&engagement_commands)
        .copied()
        .collect();
    let envelope = input::aggregate::<serde_json::Value>(bytes, &allowed)
        .map_err(|error| invalid(error.to_string()))?;
    if security_commands.contains(&envelope.command.as_str()) {
        let result: Report =
            serde_json::from_value(envelope.result).map_err(|error| invalid(error.to_string()))?;
        if result.kind != envelope.command {
            return Err(invalid("report kind does not match command"));
        }
        return Ok(result);
    }
    engagement(&envelope.command, envelope.result)
}

fn is_plan(command: &str, result: &serde_json::Value) -> bool {
    let Some(fields) = result.as_object() else {
        return false;
    };
    (command == Command::Scan.as_str() && fields.contains_key("targets"))
        || (command == Command::Differential.as_str() && fields.contains_key("token"))
}

#[derive(serde::Deserialize)]
struct ScanEndpoint {
    #[serde(default)]
    classification: String,
}

#[derive(serde::Deserialize, Default)]
struct ScanScheduling {
    #[serde(default)]
    incomplete: Vec<serde::de::IgnoredAny>,
}

#[derive(serde::Deserialize, Default)]
struct ScanResult {
    #[serde(default)]
    scheduling: Option<ScanScheduling>,
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    endpoints: Vec<ScanEndpoint>,
    #[serde(default)]
    hosts: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    resolved_addresses: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    undecoded: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    unattributed: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    retained_evidence_bytes: Option<u64>,
}

#[derive(serde::Deserialize, Default)]
struct DifferentialRow {
    #[serde(default)]
    verdict: String,
}

#[derive(serde::Deserialize, Default)]
struct DifferentialResult {
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    provisional: Option<bool>,
    #[serde(default)]
    plan_digest: Option<String>,
    #[serde(default)]
    source_port: u64,
    #[serde(default)]
    rows: Vec<DifferentialRow>,
    #[serde(default)]
    attempts: Vec<serde::de::IgnoredAny>,
}

#[derive(serde::Deserialize, Default)]
struct FuzzResult {
    #[serde(default)]
    seed: u64,
    #[serde(default)]
    first_case: u64,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    cases_generated: u64,
    #[serde(default)]
    cases_built: u64,
    #[serde(default)]
    cases_rejected: u64,
    #[serde(default)]
    cases: Vec<serde::de::IgnoredAny>,
}

#[derive(serde::Deserialize, Default)]
struct ExchangeResult {
    #[serde(default)]
    sent: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    responses: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    unanswered: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    unsolicited: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    undecoded: Vec<serde::de::IgnoredAny>,
}

#[derive(serde::Deserialize, Default)]
struct TracerouteResult {
    #[serde(default)]
    target: Option<String>,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    strategy: Option<String>,
    #[serde(default)]
    completion: Option<String>,
    #[serde(default)]
    destination_port: Option<u64>,
    #[serde(default)]
    hops: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    resolved_addresses: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    undecoded: Vec<serde::de::IgnoredAny>,
    #[serde(default)]
    retained_evidence_bytes: Option<u64>,
}

enum Engagement {
    Scan(ScanResult),
    Differential(DifferentialResult),
    Fuzz(FuzzResult),
    Exchange(ExchangeResult),
    Traceroute(TracerouteResult),
}

fn engagement(command: &str, result: serde_json::Value) -> Result<Report, CliError> {
    if is_plan(command, &result) {
        return Err(invalid(
            "engagement plans are not executed results, run the command without --list or --plan-only first",
        ));
    }
    let typed = match command {
        command if command == Command::Scan.as_str() => serde_json::from_value(result)
            .map(Engagement::Scan)
            .map_err(|error| invalid(error.to_string())),
        command if command == Command::Differential.as_str() => serde_json::from_value(result)
            .map(Engagement::Differential)
            .map_err(|error| invalid(error.to_string())),
        command if command == Command::Fuzz.as_str() => serde_json::from_value(result)
            .map(Engagement::Fuzz)
            .map_err(|error| invalid(error.to_string())),
        command if command == Command::Exchange.as_str() => serde_json::from_value(result)
            .map(Engagement::Exchange)
            .map_err(|error| invalid(error.to_string())),
        _ => serde_json::from_value(result)
            .map(Engagement::Traceroute)
            .map_err(|error| invalid(error.to_string())),
    }?;
    Ok(summarize(command, typed))
}

fn count_by<'a>(
    names: impl IntoIterator<Item = &'a str>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut counts = serde_json::Map::new();
    for name in names {
        if name.is_empty() {
            continue;
        }
        let count = counts
            .entry(name.to_owned())
            .or_insert(serde_json::json!(0));
        *count = serde_json::json!(count.as_u64().unwrap_or(0) + 1);
    }
    counts
}

fn summarize(command: &str, result: Engagement) -> Report {
    use packetcraftr_core::security::{Finding, Severity};
    let mut report = Report::new(command);
    report
        .measurements
        .insert("engagement_command".into(), serde_json::json!(command));
    let mut summary = serde_json::Map::new();
    let put = |summary: &mut serde_json::Map<String, serde_json::Value>,
               key: &str,
               value: serde_json::Value| {
        summary.insert(key.to_owned(), value);
    };
    match &result {
        Engagement::Scan(scan) => {
            put(
                &mut summary,
                "endpoints",
                serde_json::json!(scan.endpoints.len()),
            );
            put(&mut summary, "hosts", serde_json::json!(scan.hosts.len()));
            put(
                &mut summary,
                "resolved_addresses",
                serde_json::json!(scan.resolved_addresses.len()),
            );
            put(
                &mut summary,
                "undecoded",
                serde_json::json!(scan.undecoded.len()),
            );
            put(
                &mut summary,
                "unattributed",
                serde_json::json!(scan.unattributed.len()),
            );
            if let Some(target) = &scan.target {
                put(&mut summary, "target", serde_json::json!(target));
            }
            if let Some(bytes) = scan.retained_evidence_bytes {
                put(
                    &mut summary,
                    "retained_evidence_bytes",
                    serde_json::json!(bytes),
                );
            }
            if let Some(scheduling) = &scan.scheduling
                && !scheduling.incomplete.is_empty()
            {
                put(
                    &mut summary,
                    "incomplete_hosts",
                    serde_json::json!(scheduling.incomplete.len()),
                );
                report.completeness.note(format!(
                    "scan scheduling left {} host(s) incomplete",
                    scheduling.incomplete.len()
                ));
            }
            let classifications = count_by(
                scan.endpoints
                    .iter()
                    .map(|endpoint| endpoint.classification.as_str()),
            );
            put(
                &mut summary,
                "classifications",
                serde_json::Value::Object(classifications),
            );
        }
        Engagement::Differential(differential) => {
            put(
                &mut summary,
                "rows",
                serde_json::json!(differential.rows.len()),
            );
            put(
                &mut summary,
                "attempts",
                serde_json::json!(differential.attempts.len()),
            );
            put(
                &mut summary,
                "source_port",
                serde_json::json!(differential.source_port),
            );
            if let Some(valid) = differential.valid {
                put(&mut summary, "valid", serde_json::json!(valid));
            }
            if let Some(provisional) = differential.provisional {
                put(&mut summary, "provisional", serde_json::json!(provisional));
            }
            if let Some(digest) = &differential.plan_digest {
                put(&mut summary, "plan_digest", serde_json::json!(digest));
            }
            let verdicts = count_by(differential.rows.iter().map(|row| row.verdict.as_str()));
            put(
                &mut summary,
                "verdicts",
                serde_json::Value::Object(verdicts),
            );
            if differential.valid == Some(false) {
                report
                    .completeness
                    .note("differential Campaign was not valid, its Baseline was not accepted");
            }
            if differential.provisional == Some(true) {
                report
                    .completeness
                    .note("differential Campaign is provisional until differential-join");
            }
        }
        Engagement::Fuzz(fuzz) => {
            put(&mut summary, "seed", serde_json::json!(fuzz.seed));
            put(
                &mut summary,
                "first_case",
                serde_json::json!(fuzz.first_case),
            );
            put(
                &mut summary,
                "cases_generated",
                serde_json::json!(fuzz.cases_generated),
            );
            put(
                &mut summary,
                "cases_built",
                serde_json::json!(fuzz.cases_built),
            );
            put(
                &mut summary,
                "cases_rejected",
                serde_json::json!(fuzz.cases_rejected),
            );
            put(&mut summary, "cases", serde_json::json!(fuzz.cases.len()));
            if let Some(mode) = &fuzz.mode {
                put(&mut summary, "mode", serde_json::json!(mode));
            }
        }
        Engagement::Exchange(exchange) => {
            put(&mut summary, "sent", serde_json::json!(exchange.sent.len()));
            put(
                &mut summary,
                "responses",
                serde_json::json!(exchange.responses.len()),
            );
            put(
                &mut summary,
                "unanswered",
                serde_json::json!(exchange.unanswered.len()),
            );
            put(
                &mut summary,
                "unsolicited",
                serde_json::json!(exchange.unsolicited.len()),
            );
            put(
                &mut summary,
                "undecoded",
                serde_json::json!(exchange.undecoded.len()),
            );
        }
        Engagement::Traceroute(trace) => {
            put(&mut summary, "hops", serde_json::json!(trace.hops.len()));
            put(
                &mut summary,
                "resolved_addresses",
                serde_json::json!(trace.resolved_addresses.len()),
            );
            put(
                &mut summary,
                "undecoded",
                serde_json::json!(trace.undecoded.len()),
            );
            for (key, value) in [
                ("target", &trace.target),
                ("destination", &trace.destination),
                ("strategy", &trace.strategy),
                ("completion", &trace.completion),
            ] {
                if let Some(value) = value {
                    put(&mut summary, key, serde_json::json!(value));
                }
            }
            if let Some(port) = trace.destination_port {
                put(&mut summary, "destination_port", serde_json::json!(port));
            }
            if let Some(bytes) = trace.retained_evidence_bytes {
                put(
                    &mut summary,
                    "retained_evidence_bytes",
                    serde_json::json!(bytes),
                );
            }
        }
    }
    report.findings.push(Finding::new(
        &format!("engagement.{command}.summary"),
        Severity::Info,
        command.to_owned(),
        "Imported engagement evidence summary, observations only and not a vulnerability finding",
        serde_json::Value::Object(summary),
        "Review the linked source result for the full evidence",
    ));
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn current_hunt() -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../examples/documents/output-hunt-success.json"),
        )
        .unwrap()
    }

    fn hunt_with_schema(schema: &str) -> Vec<u8> {
        let mut value: serde_json::Value = serde_json::from_slice(&current_hunt()).unwrap();
        value["schema"] = serde_json::Value::from(schema);
        serde_json::to_vec(&value).unwrap()
    }

    fn rejection(bytes: &[u8]) -> String {
        report(bytes).unwrap_err().message
    }

    #[test]
    fn current_security_output_is_accepted() {
        assert_eq!(report(&current_hunt()).unwrap().kind, "hunt");
    }

    #[test]
    fn engagement_results_are_summarized_not_copied() {
        let read_example = |name: &str| {
            std::fs::read(
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../examples/documents")
                    .join(name),
            )
            .unwrap()
        };
        let scan = report(&read_example("output-scan-success.json")).unwrap();
        assert_eq!(scan.kind, "scan");
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.findings[0].rule_id, "engagement.scan.summary");
        assert_eq!(scan.findings[0].evidence["endpoints"], 1);
        assert_eq!(scan.findings[0].evidence["classifications"]["timeout"], 1);
        assert!(scan.completeness.complete);

        let differential = report(&read_example("output-differential-success.json")).unwrap();
        assert_eq!(differential.kind, "differential");
        assert_eq!(
            differential.findings[0].evidence["verdicts"]["accepted"],
            differential.findings[0].evidence["rows"]
        );
        assert!(differential.findings[0].evidence["plan_digest"].is_string());

        for (name, kind, field) in [
            ("output-fuzz-success.json", "fuzz", "cases_generated"),
            ("output-exchange-success.json", "exchange", "responses"),
            ("output-traceroute-success.json", "traceroute", "hops"),
        ] {
            let imported = report(&read_example(name)).unwrap();
            assert_eq!(imported.kind, kind, "{name}");
            assert!(imported.findings[0].evidence[field].is_number(), "{name}");
        }

        for plan in [
            "output-scan-list-aggregate.json",
            "output-differential-plan-success.json",
        ] {
            let error = report(&read_example(plan)).unwrap_err();
            assert!(
                error.message.contains("not executed"),
                "{plan}: {}",
                error.message
            );
        }

        let mut incomplete: serde_json::Value =
            serde_json::from_slice(&read_example("output-scan-success.json")).unwrap();
        incomplete["result"]["scheduling"]["incomplete"] =
            serde_json::json!([{"address": "192.0.2.1"}]);
        let imported = report(&serde_json::to_vec(&incomplete).unwrap()).unwrap();
        assert!(!imported.completeness.complete);
        assert_eq!(imported.findings[0].evidence["incomplete_hosts"], 1);

        let build = read_example("output-build-success.json");
        assert!(report(&build).is_err());
    }

    #[test]
    fn v1_reports_require_regeneration() {
        let message = rejection(&hunt_with_schema("packetcraftr.output/v1"));
        assert!(message.contains("ambiguous"), "{message}");
        assert!(message.contains("regenerate"), "{message}");
    }

    #[test]
    fn unrelated_output_identity_is_rejected() {
        let unknown = format!("{}/unsupported", packetcraftr_core::security::OUTPUT_SCHEMA);
        for schema in [
            "packetcraftr.output/v2",
            "packetcraftr.output/v18",
            &unknown,
        ] {
            let message = rejection(&hunt_with_schema(schema));
            assert!(!message.contains("ambiguous"), "{schema}: {message}");
        }
    }

    #[test]
    fn deeply_nested_report_json_is_rejected() {
        let depth = 100_000;
        let nested = [vec![b'['; depth], vec![b']'; depth]].concat();
        assert!(report(&nested).is_err());
    }

    #[test]
    fn stdin_validation_precedes_io_and_hashes_input() {
        assert!(validate_stdin_sources([Path::new("-"), Path::new("missing.json")]).is_ok());
        assert!(validate_stdin_sources([Path::new("-"), Path::new("-")]).is_err());
        assert!(validate_stdin_sources([Path::new("missing.json")]).is_ok());
        let source = source(Path::new("-"), b"abc");
        assert_eq!(source.path, "-");
        assert_eq!(
            source.sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
