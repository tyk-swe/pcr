// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use packetcraftr_core::document::service_probes::{
    self, Confidence, Corpus, Field, MatchOutcome, ObservationOutcome, Probe, ValueSource,
};

fn corpus() -> Corpus {
    service_probes::parse(include_bytes!(
        "../../../packetcraftr/data/service-probes.json"
    ))
    .expect("reviewed project corpus")
}

fn probe<'a>(corpus: &'a Corpus, id: &str) -> &'a Probe {
    corpus.probes.iter().find(|probe| probe.id == id).unwrap()
}

#[test]
fn declared_training_instances_reproduce_product_and_supported_metadata() {
    let fixtures: serde_json::Value = serde_json::from_slice(include_bytes!(
        "../../../packetcraftr/data/service-probes.training.v1.json"
    ))
    .unwrap();
    let corpus = corpus();
    assert_eq!(fixtures["corpus_version"], corpus.version);
    for fixture in fixtures["fixtures"].as_array().unwrap() {
        let probe = probe(&corpus, fixture["probe"].as_str().unwrap());
        assert!(probe.request_bytes(0).unwrap().is_empty());
        let observation = service_probes::observe(
            probe,
            fixture["response"].as_str().unwrap().as_bytes(),
            false,
        );
        assert_eq!(observation.outcome, ObservationOutcome::Complete);
        let result = corpus.identify(probe, &observation);
        assert_eq!(result.outcome, MatchOutcome::Matched);
        assert_eq!(result.candidates.len(), 1);
        let candidate = &result.candidates[0];
        assert_eq!(candidate.product, fixture["product"]);
        assert_eq!(candidate.version.as_deref(), fixture["version"].as_str());
        assert_eq!(candidate.provenance.rule, fixture["rule"]);
        assert_eq!(candidate.confidence, Confidence::Claim);
        assert!(candidate.device_type.is_none());
        let cpe = candidate.cpe.as_ref().expect("reviewed static product CPE");
        assert!(cpe.value.starts_with("cpe:2.3:a:"));
        assert!(
            matches!(&cpe.source, ValueSource::MatchRule { reference } if reference == "https://nvd.nist.gov/products/cpe")
        );
        assert_eq!(
            candidate
                .hostname
                .as_ref()
                .map(|hostname| hostname.value.as_str()),
            fixture["hostname"].as_str()
        );
        if let Some(hostname) = &candidate.hostname {
            let ValueSource::ObservedField { field, index } = &hostname.source else {
                panic!("hostname must refer to exact observed octets")
            };
            assert_eq!(*field, Field::SmtpHostname);
            assert_eq!(observation.fields[*index].value, hostname.value.as_bytes());
        }
    }
}

#[test]
fn greeting_collection_preserves_fragmentation_and_multiline_boundaries() {
    let corpus = corpus();
    for (id, wire, complete) in [
        (
            "smtp-greeting",
            "220-mail.example.test ESMTP Postfix 3.10.1\r\n220 ready\r\n",
            service_probes::smtp_collection_complete as fn(&[u8]) -> bool,
        ),
        (
            "ftp-greeting",
            "220-FTP fixture\r\nAn isolated welcome line\r\n220 ProFTPD 1.3.8 Server ready\r\n",
            service_probes::ftp_collection_complete as fn(&[u8]) -> bool,
        ),
    ] {
        for end in 0..wire.len() {
            assert!(!complete(&wire.as_bytes()[..end]), "{id}: {end}");
        }
        assert!(complete(wire.as_bytes()));
        let probe = probe(&corpus, id);
        let observation = service_probes::observe(probe, wire.as_bytes(), false);
        assert_eq!(observation.outcome, ObservationOutcome::Complete);
        assert_eq!(
            corpus.identify(probe, &observation).outcome,
            MatchOutcome::Matched
        );
        let partial = service_probes::observe(probe, wire.as_bytes(), true);
        assert!(!partial.fields.is_empty(), "retain already observed claims");
        assert_eq!(
            corpus.identify(probe, &partial).outcome,
            MatchOutcome::Truncated
        );
    }
}

#[test]
fn greeting_syntax_and_resource_boundaries_never_yield_candidates() {
    let corpus = corpus();
    for (id, wire, outcome) in [
        (
            "smtp-greeting",
            "220 mail.example.test ESMTP Postfix 3.10.1\n".into(),
            ObservationOutcome::Malformed,
        ),
        (
            "smtp-greeting",
            "220-mail.example.test ESMTP Postfix 3.10.1\r\n221 bye\r\n".into(),
            ObservationOutcome::Malformed,
        ),
        (
            "ftp-greeting",
            "220 ProFTPD 1.3.8\0ready\r\n".into(),
            ObservationOutcome::Malformed,
        ),
        (
            "smtp-greeting",
            "220-mail.example.test ESMTP Postfix 3.10.1\r\n".repeat(33),
            ObservationOutcome::Truncated,
        ),
        (
            "ftp-greeting",
            format!("220-{}\r\n", "a".repeat(1021)),
            ObservationOutcome::Truncated,
        ),
        (
            "smtp-greeting",
            format!("220 mail.example.test ESMTP {}\r\n", "a".repeat(512)),
            ObservationOutcome::Truncated,
        ),
    ] {
        let probe = probe(&corpus, id);
        let observation = service_probes::observe(probe, wire.as_bytes(), false);
        assert_eq!(observation.outcome, outcome, "{id}: {observation:?}");
        assert!(corpus.identify(probe, &observation).candidates.is_empty());
        let complete = if id == "smtp-greeting" {
            service_probes::smtp_collection_complete
        } else {
            service_probes::ftp_collection_complete
        };
        assert!(complete(wire.as_bytes()));
    }
}

#[test]
fn shared_numeric_greetings_and_unsupported_metadata_stay_unknown_or_absent() {
    let corpus = corpus();
    for (id, wire) in [
        ("smtp-greeting", "220 FTP welcome\r\n"),
        (
            "ftp-greeting",
            "220 mail.example.test ESMTP Postfix 3.10.1\r\n",
        ),
        ("smtp-greeting", "220 not_a_domain ESMTP Postfix 3.10.1\r\n"),
        (
            "smtp-greeting",
            "220 mail.example.test ESMTP Unknown 123\r\n",
        ),
        ("ftp-greeting", "220 welcome to an unknown service\r\n"),
    ] {
        let probe = probe(&corpus, id);
        let observation = service_probes::observe(probe, wire.as_bytes(), false);
        let result = corpus.identify(probe, &observation);
        assert_eq!(
            result.outcome,
            MatchOutcome::Unknown,
            "{id}: {observation:?}"
        );
        assert!(result.candidates.is_empty());
    }
    let probe = probe(&corpus, "smtp-greeting");
    let observation = service_probes::observe(probe, b"220-one.example.test ESMTP Postfix 3.10.1\r\n220 two.example.test ESMTP Postfix 3.10.1\r\n", false);
    let result = corpus.identify(probe, &observation);
    assert_eq!(result.outcome, MatchOutcome::Matched);
    assert!(
        result.candidates[0].hostname.is_none(),
        "conflicting observed hostnames do not become one asserted name"
    );
}

#[test]
fn reviewed_metadata_requires_claim_fields_and_static_cpe_values() {
    let corpus = corpus();
    let original = serde_json::to_value(&corpus).unwrap();
    for (field, replacement) in [
        ("hostname_field", serde_json::json!("http_server")),
        ("cpe", serde_json::json!("cpe:/a:postfix:postfix")),
        (
            "cpe",
            serde_json::json!("cpe:2.3:a:postfix:postfix:3.10.1:*:*:*:*:*:*:*"),
        ),
        ("device_type", serde_json::json!("bad\nvalue")),
    ] {
        let mut value = original.clone();
        value["matches"][0][field] = replacement;
        assert!(service_probes::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut corpus = corpus;
    let rule = corpus
        .matches
        .iter_mut()
        .find(|rule| rule.id == "postfix-claim")
        .unwrap();
    rule.device_type = Some("explicit fixture device".into());
    rule.cpe = None;
    rule.metadata.reference = "project-authored device fixture".into();
    let probe = probe(&corpus, "smtp-greeting");
    let result = corpus.identify(
        probe,
        &service_probes::observe(
            probe,
            b"220 mail.example.test ESMTP Postfix 3.10.1\r\n",
            false,
        ),
    );
    let device = result.candidates[0].device_type.as_ref().unwrap();
    assert_eq!(device.value, "explicit fixture device");
    assert!(
        matches!(&device.source, ValueSource::MatchRule { reference } if reference == "project-authored device fixture")
    );
    let rule = corpus
        .matches
        .iter_mut()
        .find(|rule| rule.id == "dns-protocol-tcp")
        .unwrap();
    rule.device_type = Some("unsupported device".into());
    assert!(corpus.validate().is_err());
}
