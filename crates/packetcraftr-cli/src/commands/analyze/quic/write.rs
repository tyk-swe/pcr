use super::output::{EarlyData, Stream};
use crate::{
    errors::CliError,
    invocation::Invocation,
    publication::{bounded_json_len, write_pretty_json_buffered},
    staged_output::StagedFile,
};
use packetcraftr_core::error::Kind;
use serde::Serialize;
use serde_json::ser::{CompactFormatter, PrettyFormatter};
use std::io::Write;
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct ExportedConnection {
    connection: u64,
    early_data: EarlyData,
    incomplete: bool,
    streams: Vec<Stream>,
}
#[derive(Serialize)]
struct Manifest {
    schema: &'static str,
    connections: Vec<ExportedConnection>,
}
pub(super) struct Exporter {
    directory: PathBuf,
    manifest: StagedFile,
    max_connections: usize,
    files: Vec<(PathBuf, StagedFile)>,
    connections: Vec<ExportedConnection>,
    charged_connection_bytes: usize,
}
impl Exporter {
    pub(super) fn new(
        invocation: &Invocation,
        directory: &Path,
        max_connections: usize,
    ) -> Result<Self, CliError> {
        if !directory.is_dir() {
            return Err(CliError::new(
                Kind::Usage,
                "QUIC export requires an existing directory",
            ));
        }
        Ok(Self {
            directory: directory.to_owned(),
            manifest: StagedFile::stage(invocation, &directory.join("quic-manifest.json"))?,
            max_connections,
            files: Vec::new(),
            connections: Vec::new(),
            charged_connection_bytes: 0,
        })
    }
    pub(super) fn range(&mut self, name: &str, data: &[u8]) -> Result<(), CliError> {
        if self.files.len() >= 4096 {
            return Err(CliError::new(
                Kind::Policy,
                "QUIC export exceeded 4096 range files",
            ));
        }
        let path = self.directory.join(name);
        let mut file = self.manifest.stage_sibling(std::ffi::OsStr::new(name))?;
        file.as_file_mut()
            .write_all(data)
            .map_err(|e| CliError::caused(Kind::Io, &e))?;
        self.files.push((path, file));
        Ok(())
    }
    pub(super) fn connection(
        &mut self,
        connection: u64,
        early_data: EarlyData,
        incomplete: bool,
        streams: &[Stream],
        remaining: usize,
    ) -> Result<usize, CliError> {
        if self.connections.len() >= self.max_connections {
            return Err(CliError::new(
                Kind::Policy,
                "QUIC export connection limit exceeded",
            ));
        }
        let exported = ExportedConnection {
            connection,
            early_data,
            incomplete,
            streams: streams
                .iter()
                .cloned()
                .map(|mut s| {
                    for r in &mut s.ranges {
                        r.data_hex = None;
                    }
                    s
                })
                .collect(),
        };
        let length = bounded_json_len(&exported, remaining, CompactFormatter)
            .map_err(|error| error.into_cli_error(manifest_limit_error))?;
        self.connections.push(exported);
        self.charged_connection_bytes += length;
        Ok(length)
    }
    pub(super) fn mark_capture_incomplete(&mut self) {
        for connection in &mut self.connections {
            connection.incomplete = true;
        }
    }
    pub(super) fn finish(mut self, remaining: usize) -> Result<usize, CliError> {
        let contents = Manifest {
            schema: "packetcraftr.quic-streams/v1",
            connections: self.connections,
        };
        let json_limit = (remaining + self.charged_connection_bytes)
            .checked_sub(1)
            .ok_or_else(manifest_limit_error)?;
        let length = bounded_json_len(&contents, json_limit, PrettyFormatter::new())
            .map_err(|error| error.into_cli_error(manifest_limit_error))?;
        let path = self.directory.join("quic-manifest.json");
        let mut manifest = self.manifest;
        write_pretty_json_buffered(manifest.as_file_mut(), &contents)
            .map_err(|error| CliError::caused(Kind::Io, &error))?;
        self.files.push((path, manifest));
        crate::staged_output::publish_staged(
            self.files,
            |_, _| (),
            |mut error, published| {
                if !published.is_empty() {
                    error.causes.push(format!(
                        "already published QUIC files remain at {}",
                        published.join(", ")
                    ));
                }
                error
            },
        )?;
        Ok(json_limit - length)
    }
}

fn manifest_limit_error() -> CliError {
    CliError::new(
        Kind::Policy,
        "QUIC application output limit exceeded by export manifest",
    )
}
