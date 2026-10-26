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
    let framing = csp.iter().any(|value| policy::framing_csp(value))
        || values("x-frame-options")
            .iter()
            .any(|v| ["deny", "sameorigin"].contains(&v.trim().to_ascii_lowercase().as_str()));
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
    fn secure_headers_pass_and_cookie_values_never_escape() {
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
    fn referrer_fallback_and_wildcard_framing_are_not_overstated() {
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

    #[test]
    fn only_the_first_hsts_field_is_effective() {
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
    fn cookie_attribute_whitespace_does_not_hide_protection() {
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
    fn the_last_samesite_attribute_is_not_skipped_when_bare() {
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
