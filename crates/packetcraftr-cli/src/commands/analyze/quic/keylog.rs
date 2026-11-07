use crate::{errors::CliError, invocation::Invocation};
use packetcraftr_core::analysis::quic::Collector;
use packetcraftr_core::error::Kind;
use std::fs::File;
use std::io::Read;
use std::path::Path;

pub(super) struct Input {
    file: Option<File>,
    read: u64,
}
impl Input {
    pub(super) fn open(path: Option<&Path>) -> Result<Self, CliError> {
        let file = path
            .map(|path| {
                let metadata =
                    std::fs::metadata(path).map_err(|error| CliError::caused(Kind::Io, &error))?;
                if !metadata.is_file() {
                    return Err(CliError::new(
                        Kind::Usage,
                        "TLS key log must be a regular file",
                    ));
                }
                File::open(path).map_err(|error| CliError::caused(Kind::Io, &error))
            })
            .transpose()?;
        Ok(Self { file, read: 0 })
    }
    pub(super) fn poll(
        &mut self,
        collector: &mut Collector,
        invocation: &Invocation,
        finish: bool,
    ) -> Result<(), CliError> {
        let Some(file) = &mut self.file else {
            return Ok(());
        };
        let deadline = invocation.control.io_control();
        let mut buffer = [0_u8; 8192];
        let mut batches = 0;
        loop {
            deadline.enforce().map_err(CliError::classified)?;
            if !finish && batches == 32 {
                return Ok(());
            }
            let length = file
                .read(&mut buffer)
                .map_err(|e| CliError::caused(Kind::Io, &e))?;
            if length == 0 {
                collector.append_keylog(&[], finish);
                return Ok(());
            }
            self.read = self.read.saturating_add(length as u64);
            if self.read > 64 * 1024 * 1024 {
                return Err(CliError::new(
                    Kind::Policy,
                    "TLS key log input exceeded 64 MiB",
                ));
            }
            collector.append_keylog(&buffer[..length], false);
            batches += 1;
        }
    }
}
