// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use super::{Request, WORKFLOW};
use crate::{
    policy::Authorizer,
    probe::{Error, ErrorKind},
    target::{SelectionError, Specification, Target, resolve_selected},
};
use packetcraftr_core::budget::Deadline;
use std::{collections::HashSet, net::IpAddr};

pub(super) fn resolve<A: Authorizer>(
    request: &Request,
    authorizer: &mut A,
    deadline: &Deadline,
) -> Result<Vec<IpAddr>, Error> {
    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    let mut specifications = HashSet::new();
    let mut candidates = 0usize;
    let fail = |source| Error::new(WORKFLOW, ErrorKind::TargetSelection(source));
    for specification in &request.targets.include {
        if !specifications.insert(specification) {
            continue;
        }
        let targets: Box<dyn Iterator<Item = Target> + '_> = match specification {
            Specification::Target(target) => Box::new(std::iter::once(target.clone())),
            Specification::Network(network) => Box::new(
                network
                    .addresses(crate::target::MAX_CANDIDATES)
                    .map_err(fail)?
                    .map(Target::Address),
            ),
        };
        for target in targets {
            crate::probe::enforce_deadline(WORKFLOW, deadline)?;
            candidates = candidates
                .checked_add(1)
                .filter(|count| *count <= 100_000)
                .ok_or_else(|| {
                    fail(SelectionError::Limit {
                        field: "target_candidates",
                        limit: 100_000,
                    })
                })?;
            if let Target::Address(address) = target
                && (request.targets.excludes(address)
                    || seen.contains(&address)
                    || !request.address_family.accepts(address))
            {
                continue;
            }
            let resolved = resolve_selected(
                authorizer,
                &target,
                request.address_family,
                deadline,
                &WORKFLOW,
            )?;
            for address in resolved.addresses {
                crate::probe::enforce_deadline(WORKFLOW, deadline)?;
                if request.targets.excludes(address) || !seen.insert(address) {
                    continue;
                }
                if selected.len() >= request.limits.max_targets {
                    return Err(fail(SelectionError::Limit {
                        field: "max_targets",
                        limit: request.limits.max_targets,
                    }));
                }
                selected.push(address);
            }
        }
    }
    Ok(selected)
}
