// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs::File,
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

use packetcraftr_core::error::Source;

use crate::Error;

struct Namespace {
    _file: File,
    device: u64,
    inode: u64,
}

impl Namespace {
    fn capture(path: &Path) -> Result<Self, Error> {
        let file = File::open(path).map_err(namespace_error)?;
        let metadata = file.metadata().map_err(namespace_error)?;
        Ok(Self {
            _file: file,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }

    fn verify(&self, path: &Path) -> Result<(), Error> {
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

const THREAD_ROOT: &str = "/proc/thread-self";
const NETWORK_NAMESPACE: &str = "ns/net";
const USER_NAMESPACE: &str = "ns/user";
const STATUS: &str = "status";
const SECURITY_LABEL: &str = "attr/current";
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

struct Snapshot {
    root: PathBuf,
    network_namespace: Namespace,
    user_namespace: Namespace,
    credentials: String,
    security_label: Vec<u8>,
}

impl Snapshot {
    fn capture(root: &Path) -> Result<Self, Error> {
        Ok(Self {
            root: root.to_owned(),
            network_namespace: Namespace::capture(&root.join(NETWORK_NAMESPACE))?,
            user_namespace: Namespace::capture(&root.join(USER_NAMESPACE))?,
            credentials: credentials(root)?,
            security_label: std::fs::read(root.join(SECURITY_LABEL)).map_err(credential_error)?,
        })
    }

    fn verify(&self) -> Result<(), Error> {
        let root = &self.root;
        self.network_namespace
            .verify(&root.join(NETWORK_NAMESPACE))?;
        self.user_namespace.verify(&root.join(USER_NAMESPACE))?;
        if credentials(root)? != self.credentials
            || std::fs::read(root.join(SECURITY_LABEL)).map_err(credential_error)?
                != self.security_label
        {
            return Err(Error::Privilege {
                message: "transmission session credentials changed".to_owned(),
                source: None,
            });
        }
        Ok(())
    }
}

pub(super) enum Reuse {
    Verified,
    Unavailable,
}

/// A session may retain a handle only while it holds a matching snapshot of the
/// creating context. Without a snapshot every send opens its own handle under
/// the credentials current at that moment, so no handle can outlive a change.
pub(super) struct ExecutionContext(Option<Snapshot>);

impl ExecutionContext {
    pub(super) fn capture() -> Self {
        Self::capture_at(Path::new(THREAD_ROOT))
    }

    pub(super) fn capture_at(root: &Path) -> Self {
        Self(Snapshot::capture(root).ok())
    }

    pub(super) fn verify(&self) -> Result<Reuse, Error> {
        let Some(snapshot) = &self.0 else {
            return Ok(Reuse::Unavailable);
        };
        snapshot.verify().map(|()| Reuse::Verified)
    }
}

fn credentials(root: &Path) -> Result<String, Error> {
    let status = std::fs::read_to_string(root.join(STATUS)).map_err(credential_error)?;
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
pub(in crate::platform::transmit) mod tests {
    use super::*;

    fn status() -> String {
        CREDENTIAL_FIELDS
            .iter()
            .map(|field| format!("{field}:\t1\n"))
            .collect()
    }

    pub(in crate::platform::transmit) fn thread_root() -> tempfile::TempDir {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join("ns")).unwrap();
        std::fs::create_dir_all(root.path().join("attr")).unwrap();
        std::fs::write(root.path().join(NETWORK_NAMESPACE), "").unwrap();
        std::fs::write(root.path().join(USER_NAMESPACE), "").unwrap();
        std::fs::write(root.path().join(SECURITY_LABEL), "label").unwrap();
        std::fs::write(root.path().join(STATUS), status()).unwrap();
        root
    }

    #[test]
    fn complete_context_permits_reuse() {
        let root = thread_root();
        assert!(matches!(
            ExecutionContext::capture_at(root.path()).verify(),
            Ok(Reuse::Verified)
        ));
    }

    #[test]
    fn missing_metadata_disables_reuse_instead_of_failing() {
        let without_seccomp_filters = thread_root();
        std::fs::write(
            without_seccomp_filters.path().join(STATUS),
            status().replace("Seccomp_filters:\t1\n", ""),
        )
        .unwrap();
        let without_label = thread_root();
        std::fs::remove_file(without_label.path().join(SECURITY_LABEL)).unwrap();
        let without_namespace = thread_root();
        std::fs::remove_file(without_namespace.path().join(USER_NAMESPACE)).unwrap();

        for root in [without_seccomp_filters, without_label, without_namespace] {
            assert!(matches!(
                ExecutionContext::capture_at(root.path()).verify(),
                Ok(Reuse::Unavailable)
            ));
        }
    }

    #[test]
    fn captured_context_rejects_every_later_change() {
        let credential_changes = [
            (STATUS, status().replace("CapEff:\t1", "CapEff:\t0")),
            (STATUS, status().replace("Seccomp_filters:\t1\n", "")),
            (SECURITY_LABEL, "other".to_owned()),
        ];
        for (file, contents) in credential_changes {
            let root = thread_root();
            let context = ExecutionContext::capture_at(root.path());
            std::fs::write(root.path().join(file), contents).unwrap();
            assert!(matches!(context.verify(), Err(Error::Privilege { .. })));
        }

        for namespace in [NETWORK_NAMESPACE, USER_NAMESPACE] {
            let root = thread_root();
            let context = ExecutionContext::capture_at(root.path());
            let path = root.path().join(namespace);
            std::fs::remove_file(&path).unwrap();
            std::fs::write(&path, "").unwrap();
            assert!(matches!(context.verify(), Err(Error::Send { .. })));
        }

        let root = thread_root();
        let context = ExecutionContext::capture_at(root.path());
        std::fs::remove_file(root.path().join(STATUS)).unwrap();
        assert!(matches!(context.verify(), Err(Error::Privilege { .. })));
    }

    #[test]
    fn credentials_detect_privilege_drops_and_omissions() {
        let status = status();
        let original = parse_credentials(&status).unwrap();
        let dropped = status.replace("CapEff:\t1", "CapEff:\t0");
        assert_ne!(parse_credentials(&dropped).unwrap(), original);
        assert!(parse_credentials(&status.replace("Uid:\t1\n", "")).is_none());
        assert!(parse_credentials(&format!("{status}CapEff:\t0\n")).is_none());
    }
}
