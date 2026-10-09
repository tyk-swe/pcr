// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use bytes::Bytes;
use packetcraftr_core::{
    document::{
        service_exclusions,
        service_probes::{
            self, Confidence, Corpus, Field, MatchOutcome, ObservationOutcome, Probe, Transport,
        },
    },
    protocol::application::dns::{Dns, Record, RecordValue},
};
use serde_json::{Value, json};

fn corpus() -> Corpus {
    service_probes::parse(include_bytes!(
        "../../../packetcraftr/data/service-probes.json"
    ))
    .expect("reviewed project corpus")
}

fn probe<'a>(corpus: &'a Corpus, id: &str) -> &'a Probe {
    corpus
        .probes
        .iter()
        .find(|probe| probe.id == id)
        .expect("fixture probe")
}

#[test]
fn known_ssh_and_http_claims_keep_observations_separate_from_candidates() {
    let corpus = corpus();
    for (id, wire, product, version, claim_field) in [
        ("ssh-banner", b"Notice: isolated fixture\r\nSSH-2.0-OpenSSH_9.8p1 fixture\r\n".as_slice(), "OpenSSH", "9.8p1", Field::SshSoftware),
        ("http-head", b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.2\r\n\r\n".as_slice(), "nginx", "1.26.2", Field::HttpServer),
        ("http-head", b"HTTP/1.0 302 Found\r\nServer: Apache/2.4.62 (fixture)\r\nLocation: http://example.invalid/\r\n\r\n".as_slice(), "Apache HTTP Server", "2.4.62", Field::HttpServer),
    ] {
        let probe = probe(&corpus, id);
        let observation = service_probes::observe(probe, wire, false);
        assert_eq!(observation.outcome, ObservationOutcome::Complete);
        assert!(observation.fields.iter().any(|field| field.field == claim_field));
        let identification = corpus.identify(probe, &observation);
        assert_eq!(identification.outcome, MatchOutcome::Matched, "{id}: {observation:?}");
        let candidate = &identification.candidates[0];
        assert_eq!(candidate.product, product);
        assert_eq!(candidate.version.as_deref(), Some(version));
        assert_eq!(candidate.confidence, Confidence::Claim);
        assert_eq!(candidate.provenance.corpus, corpus.name);
        assert_eq!(candidate.provenance.version, corpus.version);
        assert_eq!(candidate.provenance.probe, probe.id);
        assert_eq!(candidate.provenance.field_indices.len(), 1);
    }
}

#[test]
fn known_dns_and_txt_claims_reuse_core_protocol_parsing() {
    let corpus = corpus();
    for id in ["dns-tcp", "dns-udp", "dns-version-tcp", "dns-version-udp"] {
        let probe = probe(&corpus, id);
        let query = probe.request_bytes(1234).expect("read-only query");
        let mut reply = Dns::try_from(query.as_slice()).expect("core DNS encoding");
        assert_eq!(reply.id, 1234);
        assert!(!reply.recursion_desired);
        reply.edit(|reply| {
            reply.response = true;
            if id.contains("version") {
                reply.answers.push(Record {
                    owner: reply.questions[0].name.clone(),
                    class: 3,
                    ttl: 0,
                    value: RecordValue::Txt(vec![Bytes::from_static(b"BIND 9.18.30")]),
                });
            }
        });
        let wire = reply.to_wire().expect("reply");
        let observation = service_probes::observe(probe, &wire, false);
        assert_eq!(observation.outcome, ObservationOutcome::Complete);
        let identification = corpus.identify(probe, &observation);
        assert_eq!(
            identification.outcome,
            MatchOutcome::Matched,
            "{id}: {observation:?}"
        );
        let candidate = &identification.candidates[0];
        if id.contains("version") {
            assert_eq!(candidate.product, "BIND");
            assert_eq!(candidate.version.as_deref(), Some("9.18.30"));
            assert_eq!(candidate.confidence, Confidence::Claim);
        } else {
            assert_eq!(candidate.product, "DNS service");
            assert_eq!(candidate.version, None);
            assert_eq!(candidate.confidence, Confidence::Protocol);
        }
    }
}

#[test]
fn unknown_services_and_unknown_software_never_invent_versions() {
    let corpus = corpus();
    for (id, wire) in [
        (
            "ssh-banner",
            b"welcome to an unknown service\r\n".as_slice(),
        ),
        ("ssh-banner", b"SSH-2.0-UnknownSoftware_8.3\r\n".as_slice()),
        (
            "http-head",
            b"HTTP/1.0 200 OK\r\nServer: Unknown/123\r\n\r\n".as_slice(),
        ),
    ] {
        let probe = probe(&corpus, id);
        let observation = service_probes::observe(probe, wire, false);
        let identification = corpus.identify(probe, &observation);
        assert_eq!(identification.outcome, MatchOutcome::Unknown);
        assert!(identification.candidates.is_empty());
    }
}

#[test]
fn ambiguous_products_and_versions_erase_every_exact_version() {
    let corpus = corpus();
    let probe = probe(&corpus, "http-head");
    for wire in [
        b"HTTP/1.0 200 OK\r\nServer: nginx/1.26.2\r\nServer: Apache/2.4.62\r\n\r\n".as_slice(),
        b"HTTP/1.0 200 OK\r\nServer: nginx/1.26.2\r\nServer: nginx/1.24.0\r\n\r\n".as_slice(),
    ] {
        let observation = service_probes::observe(probe, wire, false);
        let identification = corpus.identify(probe, &observation);
        assert_eq!(identification.outcome, MatchOutcome::Ambiguous);
        assert_eq!(identification.candidates.len(), 2);
        assert!(
            identification
                .candidates
                .iter()
                .all(|candidate| candidate.version.is_none())
        );
    }
}

#[test]
fn misleading_banner_is_only_an_unauthenticated_claim() {
    let corpus = corpus();
    let probe = probe(&corpus, "ssh-banner");
    // Any endpoint can send these bytes, regardless of the software it runs.
    let forged = b"SSH-2.0-OpenSSH_99.999 fixture pretending to be OpenSSH\r\n";
    let observation = service_probes::observe(probe, forged, false);
    let identification = corpus.identify(probe, &observation);
    assert_eq!(identification.outcome, MatchOutcome::Matched);
    assert_eq!(identification.candidates[0].confidence, Confidence::Claim);
    assert_eq!(
        identification.candidates[0].version.as_deref(),
        Some("99.999")
    );
    assert_eq!(observation.fields[0].value, &forged[..forged.len() - 2]);
}

#[test]
fn malformed_replies_keep_their_explicit_outcome() {
    let corpus = corpus();
    for (id, wire) in [
        ("ssh-banner", b"SSH-2.0-\r\n".as_slice()),
        ("ssh-banner", b"SSH-2.0-OpenSSH_9.8p1\n".as_slice()),
        (
            "http-head",
            b"HTTP/1.1 200 OK\r\nServer: forged\x00claim\r\n\r\n".as_slice(),
        ),
        (
            "dns-udp",
            b"\x50\x43\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00".as_slice(),
        ),
    ] {
        let probe = probe(&corpus, id);
        let observation = service_probes::observe(probe, wire, false);
        assert_eq!(observation.outcome, ObservationOutcome::Malformed);
        assert!(observation.diagnostic.is_some());
        let identification = corpus.identify(probe, &observation);
        assert_eq!(identification.outcome, MatchOutcome::Malformed);
        assert!(identification.candidates.is_empty());
    }
}

#[test]
fn truncation_retains_claims_without_exact_candidates() {
    let corpus = corpus();
    for (id, wire, forced) in [
        ("ssh-banner", b"SSH-2.0-OpenSSH_9".as_slice(), false),
        (
            "http-head",
            b"HTTP/1.0 200 OK\r\nServer: nginx/1.26".as_slice(),
            false,
        ),
        ("dns-udp", b"\x50\x43\x80".as_slice(), false),
        ("ssh-banner", b"SSH-2.0-OpenSSH_9.8p1\r\n".as_slice(), true),
    ] {
        let probe = probe(&corpus, id);
        let observation = service_probes::observe(probe, wire, forced);
        assert_eq!(observation.outcome, ObservationOutcome::Truncated);
        let identification = corpus.identify(probe, &observation);
        assert_eq!(identification.outcome, MatchOutcome::Truncated);
        assert!(identification.candidates.is_empty());
        if forced {
            assert!(
                !observation.fields.is_empty(),
                "claims read before limit remain evidence"
            );
        }
    }
}

#[test]
fn matches_are_anchored_bounded_and_reproducible() {
    let corpus = corpus();
    let probe = probe(&corpus, "http-head");
    let embedded = b"HTTP/1.0 200 OK\r\nServer: pretend-nginx/1.26.2\r\n\r\n";
    let observation = service_probes::observe(probe, embedded, false);
    assert_eq!(
        corpus.identify(probe, &observation).outcome,
        MatchOutcome::Unknown
    );
    let wire = format!(
        "HTTP/1.0 200 OK\r\nServer: nginx/1.{}\r\n\r\n",
        "2".repeat(64)
    );
    let observation = service_probes::observe(probe, wire.as_bytes(), false);
    let first = corpus.identify(probe, &observation);
    assert_eq!(first.outcome, MatchOutcome::Matched);
    assert_eq!(
        first.candidates[0].version, None,
        "overlong version is never shortened"
    );
    assert_eq!(first, corpus.identify(probe, &observation));
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&corpus.identify(probe, &observation)).unwrap()
    );
}

#[test]
fn duplicate_evidence_is_grouped_and_protocol_matches_do_not_compete_with_claims() {
    let mut corpus = corpus();
    let mut rule = corpus
        .matches
        .iter()
        .find(|rule| rule.probe == "http-head")
        .unwrap()
        .clone();
    rule.id = "http-protocol".into();
    rule.field = Field::HttpStatus;
    rule.prefix = "200".into();
    rule.product = "HTTP service".into();
    rule.version = None;
    corpus.matches.push(rule);
    let probe = probe(&corpus, "http-head");
    let observation = service_probes::observe(
        probe,
        b"HTTP/1.0 200 OK\r\nServer: nginx/1.26.2\r\nServer: nginx/1.26.2\r\n\r\n",
        false,
    );
    let identification = corpus.identify(probe, &observation);
    assert_eq!(identification.outcome, MatchOutcome::Matched);
    assert_eq!(identification.candidates.len(), 2);
    assert_eq!(
        identification.candidates[0].version.as_deref(),
        Some("1.26.2")
    );
    assert_eq!(
        identification.candidates[0].provenance.field_indices,
        [1, 2]
    );
}

#[test]
fn probe_requests_are_closed_and_read_only() {
    let corpus = corpus();
    assert!(
        probe(&corpus, "ssh-banner")
            .request_bytes(0)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        probe(&corpus, "http-head").request_bytes(0).unwrap(),
        b"HEAD / HTTP/1.0\r\n\r\n"
    );
    let original: Value = serde_json::to_value(&corpus).unwrap();
    for replacement in [
        json!({"type":"dns","payload":{"type":"bytes","data":"00"}}),
        json!({"type":"dns","payload":{"type":"dns","name":"example.invalid.","recursion_desired":true}}),
        json!({"type":"http_head","method":"POST"}),
    ] {
        let mut value = original.clone();
        value["probes"][0]["request"] = replacement;
        assert!(service_probes::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    let mut value = original.clone();
    value["probes"][0]["transport"] = json!("udp");
    assert!(service_probes::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}

#[test]
fn document_and_constructed_evidence_limits_are_enforced() {
    let mut unsupported_identity = corpus();
    unsupported_identity
        .matches
        .iter_mut()
        .find(|rule| rule.field == Field::DnsRcode)
        .expect("protocol match")
        .product = "nginx".into();
    assert!(unsupported_identity.validate().is_err());

    let corpus = corpus();
    assert!(service_probes::parse(&vec![b' '; service_probes::MAX_DOCUMENT_BYTES + 1]).is_err());
    let mut value = serde_json::to_value(&corpus).unwrap();
    value["matches"][0]["metadata"] = json!({});
    assert!(service_probes::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let mut excessive = corpus.clone();
    excessive.probes = vec![corpus.probes[0].clone(); service_probes::MAX_PROBES + 1];
    assert!(excessive.validate().is_err());
    let probe = probe(&corpus, "http-head");
    let mut observation = service_probes::observe(
        probe,
        b"HTTP/1.0 200 OK\r\nServer: nginx/1.26.2\r\n\r\n",
        false,
    );
    observation.fields =
        vec![observation.fields[1].clone(); service_probes::MAX_OBSERVED_FIELDS + 1];
    assert_eq!(
        corpus.identify(probe, &observation).outcome,
        MatchOutcome::Malformed
    );
}

#[test]
fn sensitive_exclusions_are_transport_specific_and_explicitly_overridable() {
    let exclusions = service_exclusions::parse(include_bytes!(
        "../../../packetcraftr/data/service-exclusions.json"
    ))
    .expect("reviewed project exclusions");
    for transport in [Transport::Tcp, Transport::Udp] {
        assert!(exclusions.excludes(transport, 9100));
        assert!(exclusions.excludes(transport, 9107));
        assert!(exclusions.excludes(transport, 502));
        assert!(!exclusions.excludes(transport, 80));
    }
    assert!(exclusions.excludes(Transport::Udp, 623));
    assert!(!exclusions.excludes(Transport::Tcp, 623));
    let empty = service_exclusions::Exclusions::empty();
    empty.validate().unwrap();
    assert!(!empty.excludes(Transport::Tcp, 9100));
    let mut value = serde_json::to_value(&exclusions).unwrap();
    value["entries"][0]["ports"] = json!([9100, 9100]);
    assert!(service_exclusions::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    value["entries"][0]["ports"] = json!([0]);
    assert!(service_exclusions::parse(&serde_json::to_vec(&value).unwrap()).is_err());
}
