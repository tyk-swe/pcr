// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Text rendering for host discovery and reverse-DNS evidence.

use super::listed;
use crate::rendering::{optional_display, write_stdout_line};
use crate::{errors::CliError, output};

/// Host records, when discovery or a reverse lookup was requested; the plan
/// line already says when neither was.
pub(super) fn render_hosts_text<P>(
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
        write_stdout_line(format_args!(
            "host {address} discovery={} scan={}",
            host.discovery, host.scan
        ))?;
        if let Some(neighbor) = &host.neighbor {
            write_stdout_line(format_args!("  {}", neighbor_text(neighbor)))?;
        }
        for reason in &host.reasons {
            write_stdout_line(format_args!(
                "  reason={} evidence={} basis={} probe={} link={} observed={}",
                reason.kind,
                reason.evidence,
                reason.basis,
                optional_display(reason.probe),
                optional_display(reason.link_address),
                optional_display(reason.observed_at.as_ref()),
            ))?;
        }
        // Discovery probes belong to no endpoint, so their evidence is shown
        // with the host it decided.
        for probe in &host.probes {
            probe_text(probe)?;
        }
        if let Some(lookup) = &host.reverse_dns {
            write_stdout_line(format_args!("  {}", reverse_dns_text(lookup)))?;
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
        optional_display(neighbor.next_hop.as_ref().map(|hop| hop.address)),
        link_text(neighbor.next_hop.as_ref().and_then(|hop| hop.link.as_ref())),
        optional_display(neighbor.observed_at.as_ref()),
    )
}

/// A host's reverse-DNS line, which marks names the scan's evidence byte
/// limit dropped so a partial list never reads as the whole answer.
fn reverse_dns_text(lookup: &output::scan::host::ReverseDns) -> String {
    format!(
        "reverse-dns={} status={} outcome={} names={} names_truncated={}{}",
        lookup.query_name,
        lookup.status,
        optional_display(lookup.outcome),
        listed(&lookup.names),
        lookup.names_truncated,
        lookup
            .error
            .as_ref()
            .map_or_else(String::new, |error| format!(" error=\"{error}\"")),
    )
}

fn link_text(link: Option<&output::scan::host::Link>) -> String {
    optional_display(link.map(|link| format!("{}/{}", link.address, link.entry.as_str())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_neighbors_carry_their_observation_time() {
        let neighbor = |observed_at| {
            output::scan::host::Neighbor::try_from(packetcraftr::scan::discovery::Neighbor {
                outcome: packetcraftr::scan::discovery::NeighborOutcome::Silent,
                interface: packetcraftr_netio::interface::Id {
                    name: "fixture0".to_owned(),
                    index: 1,
                },
                attempts: 1,
                observed_at,
            })
            .expect("a representable neighbor")
        };
        let observed = neighbor(Some(std::time::UNIX_EPOCH));
        let text = neighbor_text(&observed);
        assert!(
            text.ends_with(&format!(
                " observed={}",
                observed.observed_at.as_ref().expect("observed")
            )),
            "{text}"
        );
        assert!(neighbor_text(&neighbor(None)).ends_with(" observed=none"));
    }

    #[test]
    fn text_reverse_dns_discloses_dropped_names() {
        let lookup = output::scan::host::ReverseDns {
            names: vec!["a.example.".to_owned()],
            names_truncated: true,
            ..output::scan::host::ReverseDns::ended(
                "10.2.0.192.in-addr.arpa".to_owned(),
                crate::output::dns::QuestionStatus::Completed,
                None,
            )
        };
        assert_eq!(
            reverse_dns_text(&lookup),
            "reverse-dns=10.2.0.192.in-addr.arpa status=completed outcome=none \
             names=a.example. names_truncated=true",
        );
    }
}
