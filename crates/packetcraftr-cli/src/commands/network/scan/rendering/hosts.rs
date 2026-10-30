// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Text rendering for host discovery and reverse-DNS evidence.

use super::listed;
use crate::rendering::{render_optional, write_stdout_line};
use crate::{errors::CliError, output};

/// Host records, when discovery or a reverse lookup was requested; the plan
/// line already says when neither was.
pub(super) fn render_hosts_text<P>(
    invocation: &crate::invocation::Invocation,
    plan: &output::scan::plan::Plan,
    hosts: &[output::scan::host::Host<P>],
    probe_text: impl Fn(&P) -> Result<(), CliError>,
) -> Result<(), CliError> {
    if plan.discovery.mode == output::scan::plan::DiscoveryMode::Omitted
        && plan.discovery.reverse_dns.is_none()
    {
        return Ok(());
    }
    for host in hosts {
        let address = match &host.scope {
            Some(scope) => format!("{}%{}", host.address, scope.zone),
            None => host.address.to_string(),
        };
        write_stdout_line(
            invocation,
            format_args!(
                "host {address} discovery={} scan={}",
                host.discovery, host.scan
            ),
        )?;
        if let Some(neighbor) = &host.neighbor {
            write_stdout_line(invocation, format_args!("  {}", neighbor_text(neighbor)))?;
        }
        for reason in &host.reasons {
            write_stdout_line(
                invocation,
                format_args!(
                    "  reason={} evidence={} basis={} probe={} link={} observed={}",
                    reason.kind,
                    reason.evidence,
                    reason.basis,
                    render_optional(reason.probe, |value| value.to_string()),
                    render_optional(reason.link_address, |value| value.to_string()),
                    render_optional(reason.observed_at.as_ref(), ToString::to_string),
                ),
            )?;
        }
        // Discovery probes belong to no endpoint, so their evidence is shown
        // with the host it decided.
        for probe in &host.probes {
            probe_text(probe)?;
        }
        if let Some(lookup) = &host.reverse_dns {
            write_stdout_line(invocation, format_args!("  {}", reverse_dns_text(lookup)))?;
        }
    }
    Ok(())
}

/// A host's neighbor line, with when its outcome was observed: a silent,
/// routed, or inapplicable outcome has no reason that would carry it.
fn neighbor_text(neighbor: &output::scan::host::Neighbor) -> String {
    format!(
        "neighbor={} interface={} attempts={} link={} next-hop={} next-hop-link={} observed={}",
        neighbor.outcome,
        neighbor.interface.name,
        neighbor.attempts,
        link_text(neighbor.link.as_ref()),
        render_optional(neighbor.next_hop.as_ref().map(|hop| hop.address), |value| {
            value.to_string()
        }),
        link_text(neighbor.next_hop.as_ref().and_then(|hop| hop.link.as_ref())),
        render_optional(neighbor.observed_at.as_ref(), ToString::to_string),
    )
}

/// A host's reverse-DNS line, which marks names the scan's evidence byte
/// limit dropped so a partial list never reads as the whole answer.
fn reverse_dns_text(lookup: &output::scan::host::ReverseDns) -> String {
    format!(
        "reverse-dns={} status={} outcome={} names={} names_truncated={}{}",
        lookup.query_name,
        lookup.status,
        render_optional(lookup.outcome, |value| value.to_string()),
        listed(&lookup.names),
        lookup.names_truncated,
        lookup
            .error
            .as_ref()
            .map_or_else(String::new, |error| format!(" error=\"{error}\"")),
    )
}

fn link_text(link: Option<&output::scan::host::Link>) -> String {
    render_optional(
        link.map(|link| format!("{}/{}", link.address, link.entry.as_str())),
        |value| value.to_string(),
    )
}
