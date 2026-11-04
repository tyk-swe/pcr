// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{fs::File, os::unix::fs::MetadataExt};

use packetcraftr_core::error::Source;

use crate::Error;

struct Namespace {
    _file: File,
    device: u64,
    inode: u64,
}

impl Namespace {
    fn capture(path: &str) -> Result<Self, Error> {
        let file = File::open(path).map_err(namespace_error)?;
        let metadata = file.metadata().map_err(namespace_error)?;
        Ok(Self {
            _file: file,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn verify(&self, path: &str) -> Result<(), Error> {
        let current = std::fs::metadata(path).map_err(namespace_error)?;
        if current.dev() != self.device || current.ino() != self.inode {
            return Err(Error::Send {
                message: "transmission session namespace changed".to_owned(),
                source: None,
            });
        }
        Ok(())
    }
}

const NETWORK_NAMESPACE: &str = "/proc/thread-self/ns/net";
const USER_NAMESPACE: &str = "/proc/thread-self/ns/user";
const STATUS: &str = "/proc/thread-self/status";
const SECURITY_LABEL: &str = "/proc/thread-self/attr/current";
const CREDENTIAL_FIELDS: [&str; 11] = [
    "Uid",
    "Gid",
    "Groups",
    "CapInh",
    "CapPrm",
    "CapEff",
    "CapBnd",
    "CapAmb",
    "NoNewPrivs",
    "Seccomp",
    "Seccomp_filters",
];

pub(super) struct ExecutionContext {
    network_namespace: Namespace,
    user_namespace: Namespace,
    credentials: String,
    security_label: Vec<u8>,
}

impl ExecutionContext {
    pub(super) fn capture() -> Result<Self, Error> {
        Ok(Self {
            network_namespace: Namespace::capture(NETWORK_NAMESPACE)?,
            user_namespace: Namespace::capture(USER_NAMESPACE)?,
            credentials: credentials()?,
            security_label: std::fs::read(SECURITY_LABEL).map_err(credential_error)?,
        })
    }

    pub(super) fn verify(&self) -> Result<(), Error> {
        self.network_namespace.verify(NETWORK_NAMESPACE)?;
        self.user_namespace.verify(USER_NAMESPACE)?;
        if credentials()? != self.credentials
            || std::fs::read(SECURITY_LABEL).map_err(credential_error)? != self.security_label
        {
            return Err(Error::Privilege {
                message: "transmission session credentials changed".to_owned(),
                source: None,
            });
        }
        Ok(())
    }
}

fn credentials() -> Result<String, Error> {
    let status = std::fs::read_to_string(STATUS).map_err(credential_error)?;
    parse_credentials(&status).ok_or_else(|| Error::Privilege {
        message: "cannot verify the transmission session credentials".to_owned(),
        source: None,
    })
}

fn parse_credentials(status: &str) -> Option<String> {
    let (seen, values) = status
        .lines()
        .filter_map(|line| {
            let (name, value) = line.split_once(':')?;
            let index = CREDENTIAL_FIELDS.iter().position(|field| *field == name)?;
            Some((index, value.trim()))
        })
        .try_fold(
            (0_u16, String::new()),
            |(seen, mut values), (index, value)| {
                let bit = 1 << index;
                if seen & bit != 0 {
                    return None;
                }
                values.push_str(CREDENTIAL_FIELDS[index]);
                values.push(':');
                values.push_str(value);
                values.push('\n');
                Some((seen | bit, values))
            },
        )?;
    (seen == (1 << CREDENTIAL_FIELDS.len()) - 1).then_some(values)
}

fn namespace_error(source: std::io::Error) -> Error {
    Error::Send {
        message: "cannot verify the transmission session namespace".to_owned(),
        source: Some(Source::new(source)),
    }
}

fn credential_error(source: std::io::Error) -> Error {
    Error::Privilege {
        message: "cannot verify the transmission session credentials".to_owned(),
        source: Some(Source::new(source)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credentials_detect_privilege_drops_and_omissions() {
        let status = CREDENTIAL_FIELDS
            .iter()
            .map(|field| format!("{field}:\t1\n"))
            .collect::<String>();
        let original = parse_credentials(&status).unwrap();
        let dropped = status.replace("CapEff:\t1", "CapEff:\t0");
        assert_ne!(parse_credentials(&dropped).unwrap(), original);
        assert!(parse_credentials(&status.replace("Uid:\t1\n", "")).is_none());
        assert!(parse_credentials(&format!("{status}CapEff:\t0\n")).is_none());
    }
}
