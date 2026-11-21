// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::collections::BTreeSet;
use std::net::IpAddr;

use serde::Deserialize;

use super::Classification;
use super::connect::{Endpoint, Outcome};

pub const MATRIX_SCHEMA_V1: &str = "packetcraftr.segmentation/v1";
pub const MAX_MATRIX_DOCUMENT_BYTES: usize = 1024 * 1024;
pub const MAX_CELLS: usize = 4096;
const MAX_SEGMENTATION_LABEL_CHARS: usize = 128;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Expectation {
    Reachable,
    Refused,
    Silent,
}

impl Expectation {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reachable => "reachable",
            Self::Refused => "refused",
            Self::Silent => "silent",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cell {
    #[serde(default = "default_from")]
    pub from: String,
    pub destination: IpAddr,
    pub port: u16,
    pub expect: Expectation,
}

fn default_from() -> String {
    "this-host".to_owned()
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Matrix {
    pub schema: String,
    pub label: String,
    pub cells: Vec<Cell>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid segmentation matrix: {0}")]
pub struct InvalidMatrix(String);

impl packetcraftr_core::error::Classified for InvalidMatrix {
    fn classification(&self) -> packetcraftr_core::error::Classification {
        packetcraftr_core::error::Classification::new(
            packetcraftr_core::error::Code::CliDocumentSyntax,
            packetcraftr_core::error::Kind::Usage,
            None,
        )
    }
}

fn invalid(message: impl Into<String>) -> InvalidMatrix {
    InvalidMatrix(message.into())
}

fn check_label(field: &str, value: &str) -> Result<(), InvalidMatrix> {
    if value.trim().is_empty()
        || value.chars().count() > MAX_SEGMENTATION_LABEL_CHARS
        || value.chars().any(char::is_control)
    {
        return Err(invalid(format!(
            "segmentation {field} must be printable and 1..={MAX_SEGMENTATION_LABEL_CHARS} characters"
        )));
    }
    Ok(())
}

impl Matrix {
    pub fn parse(bytes: &[u8]) -> Result<Self, InvalidMatrix> {
        if bytes.len() > MAX_MATRIX_DOCUMENT_BYTES {
            return Err(invalid(format!(
                "segmentation matrix exceeds {MAX_MATRIX_DOCUMENT_BYTES} bytes"
            )));
        }
        let matrix: Self =
            serde_json::from_slice(bytes).map_err(|error| invalid(error.to_string()))?;
        matrix.validate()?;
        Ok(matrix)
    }

    pub fn validate(&self) -> Result<(), InvalidMatrix> {
        if self.schema != MATRIX_SCHEMA_V1 {
            return Err(invalid(format!(
                "expected schema {MATRIX_SCHEMA_V1:?}, got {:?}",
                self.schema
            )));
        }
        check_label("label", &self.label)?;
        if self.cells.is_empty() || self.cells.len() > MAX_CELLS {
            return Err(invalid(format!(
                "segmentation matrix must contain 1..={MAX_CELLS} cells"
            )));
        }
        let mut seen = BTreeSet::new();
        for cell in &self.cells {
            check_label("from", &cell.from)?;
            if cell.port == 0 {
                return Err(invalid("segmentation cell port must be non-zero"));
            }
            if cell.destination.is_unspecified() || cell.destination.is_multicast() {
                return Err(invalid(
                    "segmentation destinations must be unicast IP addresses",
                ));
            }
            if !seen.insert((cell.from.clone(), cell.destination, cell.port)) {
                return Err(invalid(format!(
                    "duplicate segmentation cell {} {}:{}",
                    cell.from, cell.destination, cell.port
                )));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn destinations(&self) -> Vec<IpAddr> {
        self.cells
            .iter()
            .map(|cell| cell.destination)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }

    #[must_use]
    pub fn ports(&self) -> Vec<u16> {
        self.cells
            .iter()
            .map(|cell| cell.port)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Pass,
    Mismatch,
    Inconclusive,
}

impl Verdict {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Mismatch => "mismatch",
            Self::Inconclusive => "inconclusive",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CellResult {
    pub cell: Cell,
    pub observed: Option<Classification>,
    pub verdict: Verdict,
}

#[must_use]
pub fn evaluate(matrix: &Matrix, endpoints: &[Endpoint]) -> Vec<CellResult> {
    matrix
        .cells
        .iter()
        .map(|cell| {
            let endpoint = endpoints.iter().find(|endpoint| {
                endpoint.address == cell.destination && endpoint.port == cell.port
            });
            let (observed, verdict) = match endpoint {
                None => (None, Verdict::Inconclusive),
                Some(endpoint) => {
                    let deadline_only = !endpoint.probes.is_empty()
                        && endpoint
                            .probes
                            .iter()
                            .all(|probe| probe.outcome == Outcome::DeadlineExpired);
                    if deadline_only
                        || matches!(
                            endpoint.classification,
                            Classification::Unknown | Classification::Unreachable
                        )
                    {
                        (Some(endpoint.classification), Verdict::Inconclusive)
                    } else {
                        let expected = match cell.expect {
                            Expectation::Reachable => Classification::Open,
                            Expectation::Refused => Classification::Closed,
                            Expectation::Silent => Classification::Timeout,
                        };
                        (
                            Some(endpoint.classification),
                            if endpoint.classification == expected {
                                Verdict::Pass
                            } else {
                                Verdict::Mismatch
                            },
                        )
                    }
                }
            };
            CellResult {
                cell: cell.clone(),
                observed,
                verdict,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::connect::ProbeEvidence;
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    fn matrix() -> Matrix {
        Matrix::parse(
            br#"{"schema":"packetcraftr.segmentation/v1","label":"zones","cells":[
              {"destination":"192.0.2.10","port":443,"expect":"reachable"},
              {"destination":"192.0.2.11","port":22,"expect":"silent"},
              {"destination":"192.0.2.12","port":25,"expect":"refused"}
            ]}"#,
        )
        .unwrap()
    }

    fn endpoint(
        address: &str,
        port: u16,
        classification: Classification,
        outcome: Outcome,
    ) -> Endpoint {
        Endpoint {
            address: address.parse().unwrap(),
            port,
            scope: None,
            classification,
            port_hint: None,
            inference: crate::scan::inference::connect([]),
            probes: vec![ProbeEvidence {
                sequence: 0,
                stage: crate::scan::Stage::Scan,
                endpoint: std::net::SocketAddr::new(address.parse().unwrap(), port),
                scope: None,
                attempt: 1,
                attempted: true,
                connect_succeeded: Some(classification == Classification::Open),
                outcome,
                scheduled_at: SystemTime::UNIX_EPOCH,
                finished_at: None,
                elapsed: Duration::ZERO,
                local: None,
                error: None,
            }],
        }
    }

    #[test]
    fn evaluates_each_expectation_and_deadline_as_inconclusive() {
        let results = evaluate(
            &matrix(),
            &[
                endpoint("192.0.2.10", 443, Classification::Open, Outcome::Connected),
                endpoint(
                    "192.0.2.11",
                    22,
                    Classification::Timeout,
                    Outcome::DeadlineExpired,
                ),
                endpoint("192.0.2.12", 25, Classification::Open, Outcome::Connected),
            ],
        );
        assert_eq!(results[0].verdict, Verdict::Pass);
        assert_eq!(results[1].verdict, Verdict::Inconclusive);
        assert_eq!(results[2].verdict, Verdict::Mismatch);
        let _ = Arc::new(());
    }

    #[test]
    fn rejects_duplicate_and_zero_port_cells() {
        assert!(Matrix::parse(br#"{"schema":"packetcraftr.segmentation/v1","label":"x","cells":[{"destination":"192.0.2.1","port":0,"expect":"reachable"}]}"#).is_err());
        assert!(Matrix::parse(br#"{"schema":"packetcraftr.segmentation/v1","label":"x","cells":[{"destination":"192.0.2.1","port":22,"expect":"reachable"},{"destination":"192.0.2.1","port":22,"expect":"silent"}]}"#).is_err());
    }
}
