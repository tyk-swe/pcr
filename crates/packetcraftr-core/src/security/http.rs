// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Finding, Report, Severity};
use crate::protocol::application::http::Head;
use serde_json::json;

mod policy;

/// Audits one final HTTP response. Cookie values are never copied into the report.
pub fn audit(head: &Head, subject: &str, https: bool) -> Report {
    let mut report = Report::new("audit-http");
    report
        .measurements
        .insert("status".into(), json!(head.status()));
    report.measurements.insert("https".into(), json!(https));
    let values = |name| {
        head.values(name)
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .collect::<Vec<_>>()
    };
    let csp = values("content-security-policy");
    let framing = policy::framing_protected(
        head.values("content-security-policy"),
        head.values("x-frame-options"),
    );
    let checks = [
        (
            "http.csp",
            !csp.iter().any(|v| !v.trim().is_empty()),
            "Content-Security-Policy is absent or empty",
            "Define a Content-Security-Policy suitable for this application.",
        ),
        (
            "http.framing",
            !framing,
            "No recognized framing protection observed",
            "Set CSP frame-ancestors or a supported X-Frame-Options policy.",
        ),
        (
            "http.nosniff",
            !values("x-content-type-options")
                .iter()
                .any(|v| v.trim().eq_ignore_ascii_case("nosniff")),
            "X-Content-Type-Options: nosniff not observed",
            "Send X-Content-Type-Options: nosniff with correct media types.",
        ),
        (
            "http.referrer_policy",
            !values("referrer-policy")
                .iter()
                .flat_map(|v| v.split(','))
                .map(|p| p.trim().to_ascii_lowercase())
                .rfind(|p| {
                    [
                        "no-referrer",
                        "no-referrer-when-downgrade",
                        "origin",
                        "origin-when-cross-origin",
                        "same-origin",
                        "strict-origin",
                        "strict-origin-when-cross-origin",
                        "unsafe-url",
                    ]
                    .contains(&p.as_str())
                })
                .is_some_and(|p| p != "unsafe-url"),
            "No recognized restrictive Referrer-Policy observed",
            "Choose an explicit Referrer-Policy appropriate for the application.",
        ),
        (
            "http.hsts",
            https
                && !head
                    .values("strict-transport-security")
                    .next()
                    .is_some_and(policy::positive_hsts),
            "Positive HTTPS Strict-Transport-Security max-age not observed",
            "After validating HTTPS deployment, configure a positive HSTS max-age.",
        ),
    ];
    for (rule, missing, summary, remediation) in checks {
        if missing {
            report.findings.push(Finding::new(
                rule,
                Severity::Low,
                subject,
                summary,
                json!({"response_status":head.status(),"request_method":"HEAD"}),
                remediation,
            ));
        }
    }
    let mut cookies = Vec::new();
    for (index, cookie) in head.values("set-cookie").enumerate() {
        let cookie = String::from_utf8_lossy(cookie);
        let mut parts = cookie.split(';');
        let name = parts
            .next()
            .and_then(|p| p.split_once('='))
            .map(|(n, _)| n.trim())
            .unwrap_or("[malformed]");
        // RFC 6265 section 5.2 trims attribute names and values separately.
        let attrs: Vec<_> = parts
            .map(|part| {
                let (name, value) = part.split_once('=').unwrap_or((part, ""));
                (
                    name.trim_matches([' ', '\t']).to_ascii_lowercase(),
                    value.trim_matches([' ', '\t']).to_ascii_lowercase(),
                )
            })
            .collect();
        let has = |name: &str| attrs.iter().any(|(key, _)| key == name);
        let same_site = attrs
            .iter()
            .rev()
            .find(|(name, _)| name == "samesite")
            .map(|(_, value)| value.as_str())
            .filter(|value| ["strict", "lax", "none"].contains(value));
        let evidence = json!({"index":index,"name":name,"value":"[redacted]","secure":has("secure"),"http_only":has("httponly"),"same_site":same_site});
        for (rule, missing, summary) in [
            (
                "http.cookie_secure",
                !has("secure"),
                "Observed cookie lacks Secure",
            ),
            (
                "http.cookie_http_only",
                !has("httponly"),
                "Observed cookie lacks HttpOnly",
            ),
            (
                "http.cookie_same_site",
                same_site.is_none() || (same_site == Some("none") && !has("secure")),
                "Observed cookie lacks valid SameSite configuration",
            ),
        ] {
            if missing {
                report.findings.push(Finding::new(rule, Severity::Low, subject, summary, evidence.clone(), "Review this cookie's purpose and set appropriate Secure, HttpOnly, and SameSite attributes."));
            }
        }
        cookies.push(evidence);
    }
    report.measurements.insert("cookies".into(), json!(cookies));
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    fn head(extra: &str) -> Head {
        crate::protocol::application::http::parse_head(&bytes::Bytes::from(format!(
            "HTTP/1.1 200 OK\r\n{extra}\r\n"
        )))
        .unwrap()
        .unwrap()
        .0
    }
    #[test]
    fn secure_headers_pass_without_leaking_cookies() {
        let h = head(
            "Content-Security-Policy: default-src 'self'; frame-ancestors 'none'\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: strict-origin\r\nStrict-Transport-Security: max-age=31536000\r\nSet-Cookie: sid=secret-token; Secure; HttpOnly; SameSite=Lax\r\n",
        );
        let report = audit(&h, "example", true);
        assert!(report.findings.is_empty());
        assert!(
            !serde_json::to_string(&report)
                .unwrap()
                .contains("secret-token")
        );
        assert!(
            audit(&head(""), "example", false)
                .findings
                .iter()
                .all(|f| f.rule_id != "http.hsts")
        );
    }
    #[test]
    fn uncertain_header_protection_remains_unconfirmed() {
        let report = audit(
            &head(
                "Referrer-Policy: no-referrer, unsafe-url\r\nContent-Security-Policy: frame-ancestors *\r\n",
            ),
            "example",
            true,
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.rule_id == "http.referrer_policy")
        );
        assert!(report.findings.iter().any(|f| f.rule_id == "http.framing"));
    }

    fn report(extra: &str) -> Report {
        let (head, _) = crate::protocol::application::http::parse_head(&bytes::Bytes::from(
            format!("HTTP/1.1 200 OK\r\n{extra}\r\n"),
        ))
        .unwrap()
        .unwrap();
        audit(&head, "example.test", true)
    }

    fn framed(extra: &[u8]) -> bool {
        let (head, _) = crate::protocol::application::http::parse_head(&bytes::Bytes::from(
            [b"HTTP/1.1 200 OK\r\n", extra, b"\r\n"].concat(),
        ))
        .unwrap()
        .unwrap();
        audit(&head, "example.test", true)
            .findings
            .iter()
            .any(|finding| finding.rule_id == "http.framing")
    }

    fn assert_framing(expected: bool, cases: &[&str]) {
        for case in cases {
            assert_eq!(framed(case.as_bytes()), expected, "{case:?}");
        }
    }

    #[test]
    fn wildcard_csp_overrides_frame_options() {
        assert!(framed(
            b"Content-Security-Policy: frame-ancestors *\r\nX-Frame-Options: DENY\r\n"
        ));
    }

    #[test]
    fn unconfirmed_csp_overrides_frame_options() {
        assert_framing(
            true,
            &[
                "Content-Security-Policy: frame-ancestors https:\r\nX-Frame-Options: DENY\r\n",
                "Content-Security-Policy: frame-ancestors https://*\r\nX-Frame-Options: DENY\r\n",
                "Content-Security-Policy: frame-ancestors\r\nX-Frame-Options: DENY\r\n",
                "Content-Security-Policy: frame-ancestors 'unsafe-inline'\r\nX-Frame-Options: DENY\r\n",
                "Content-Security-Policy: default-src 'self'; frame-ancestors *\r\nX-Frame-Options: SAMEORIGIN\r\n",
            ],
        );
    }

    #[test]
    fn frame_options_applies_without_ancestors() {
        assert_framing(
            false,
            &[
                "X-Frame-Options: DENY\r\n",
                "X-Frame-Options: sameorigin\r\n",
                "X-Frame-Options: DENY\r\nX-Frame-Options: deny\r\n",
                "X-Frame-Options: DENY, SAMEORIGIN\r\n",
                "X-Frame-Options: \"x\",deny\r\n",
                "X-Frame-Options: ALLOWALL\r\nX-Frame-Options: garbage\r\n",
                "Content-Security-Policy: default-src 'self'\r\nX-Frame-Options: DENY\r\n",
                "Content-Security-Policy-Report-Only: frame-ancestors *\r\nX-Frame-Options: DENY\r\n",
            ],
        );
        assert_framing(
            true,
            &[
                "",
                "X-Frame-Options:\r\n",
                "X-Frame-Options: ALLOWALL\r\n",
                "X-Frame-Options: garbage\r\n",
                "X-Frame-Options: ALLOW-FROM https://a.example\r\n",
                "X-Frame-Options: one, two\r\n",
                "X-Frame-Options: \"x, deny, y\"\r\n",
                "X-Frame-Options: \"x\r\nX-Frame-Options: deny\r\n",
                "X-Frame-Options: \"\\\", deny, \"\r\n",
                "X-Frame-Options: ALLOWALL\r\nX-Frame-Options: allowall\r\n",
                "Content-Security-Policy-Report-Only: frame-ancestors 'none'\r\n",
            ],
        );
    }

    #[test]
    fn restrictive_frame_ancestors_protect() {
        assert_framing(
            false,
            &[
                "Content-Security-Policy: frame-ancestors 'none'\r\n",
                "Content-Security-Policy: FrAmE-AnCeStOrS 'NONE'\r\n",
                "Content-Security-Policy: frame-ancestors 'self'\r\nX-Frame-Options: ALLOWALL\r\n",
                "Content-Security-Policy: frame-ancestors https://a.example\r\n",
                "Content-Security-Policy: frame-ancestors *.a.example a.example:443/path https://b.example:*\r\n",
                "Content-Security-Policy: frame-ancestors 'none' 'self'\r\n",
                "Content-Security-Policy: frame-ancestors 'self' 'unsafe-inline'\r\n",
            ],
        );
    }

    #[test]
    fn unrestricted_ancestors_provide_no_protection() {
        assert_framing(
            true,
            &[
                "Content-Security-Policy: frame-ancestors *\r\n",
                "Content-Security-Policy: frame-ancestors https:\r\n",
                "Content-Security-Policy: frame-ancestors https://*\r\n",
                "Content-Security-Policy: frame-ancestors 'self' *:443\r\n",
                "Content-Security-Policy: frame-ancestors 'self' https://*\r\n",
                "Content-Security-Policy: frame-ancestors 'self' https:\r\n",
                "Content-Security-Policy: frame-ancestors 'none' https://*\r\n",
                "Content-Security-Policy: frame-ancestors 'nonce-abc' 'sha256-abc='\r\n",
            ],
        );
    }

    #[test]
    fn every_enforced_policy_must_allow_framing() {
        assert_framing(
            false,
            &[
                "Content-Security-Policy: frame-ancestors *, frame-ancestors 'none'\r\n",
                "Content-Security-Policy: frame-ancestors *\r\nContent-Security-Policy: frame-ancestors 'self'\r\n",
            ],
        );
        assert_framing(
            true,
            &[
                "Content-Security-Policy: frame-ancestors *, frame-ancestors https:\r\nX-Frame-Options: DENY\r\n",
                "Content-Security-Policy: frame-ancestors *\r\nContent-Security-Policy: frame-ancestors https:\r\nX-Frame-Options: DENY\r\n",
                "Content-Security-Policy: default-src 'self', frame-ancestors *\r\nX-Frame-Options: DENY\r\n",
            ],
        );
    }

    #[test]
    fn first_frame_ancestors_directive_wins() {
        assert!(framed(
            b"Content-Security-Policy: frame-ancestors *; frame-ancestors 'none'\r\n"
        ));
        assert!(!framed(
            b"Content-Security-Policy: frame-ancestors 'none'; frame-ancestors *\r\n"
        ));
    }

    #[test]
    fn non_ascii_input_never_becomes_protection() {
        assert_framing(
            true,
            &[
                "Content-Security-Policy: frame-ancestors\u{a0}'none'\r\n",
                "Content-Security-Policy: frame-ancestors 'none'\u{a0}\r\n",
                "Content-Security-Policy: frame-ancestors 'self' \u{a0}\r\n",
                "X-Frame-Options: DENY\u{a0}\r\n",
            ],
        );
        assert!(framed(
            b"Content-Security-Policy: frame-ancestors \xff'none'\r\n"
        ));
        assert!(framed(b"X-Frame-Options: DENY\xff\r\n"));
        assert!(!framed(
            "Content-Security-Policy: frame-ancestors\u{a0}*\r\nX-Frame-Options: DENY\r\n"
                .as_bytes()
        ));
    }

    #[test]
    fn first_hsts_field_wins() {
        let report = report(
            "Strict-Transport-Security: max-age=0\r\nStrict-Transport-Security: max-age=1\r\n",
        );
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "http.hsts")
        );
    }

    #[test]
    fn cookie_whitespace_preserves_protection() {
        let report =
            report("Set-Cookie: sid=private; Secure = yes; HttpOnly = yes; SameSite = Lax\r\n");
        assert!(
            !report
                .findings
                .iter()
                .any(|finding| finding.rule_id.starts_with("http.cookie_"))
        );
        assert!(!serde_json::to_string(&report).unwrap().contains("private"));
    }

    #[test]
    fn bare_final_samesite_overrides_previous() {
        let report =
            report("Set-Cookie: sid=private; Secure; HttpOnly; SameSite=Lax; SameSite\r\n");
        assert!(
            report
                .findings
                .iter()
                .any(|finding| finding.rule_id == "http.cookie_same_site")
        );
    }
}
