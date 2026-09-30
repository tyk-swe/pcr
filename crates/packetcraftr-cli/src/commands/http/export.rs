// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

use crate::{errors::CliError, output::http::Entity, staged_output::StagedDirectory};
use packetcraftr_core::{
    analysis::{
        http::{Message, Status},
        reassembly::tcp::ScopedFlowKey,
    },
    error::Kind,
    protocol::application::http::Body,
};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

type Key = (u64, u64, u64);
struct Pending {
    file: File,
    path: PathBuf,
    bytes: u64,
}

pub(super) struct Export {
    staged: StagedDirectory,
    destination: PathBuf,
    pending: BTreeMap<Key, Pending>,
    decode: bool,
    maximum: u64,
    written: u64,
    max_body: u64,
}

impl Export {
    pub(super) fn new(
        destination: &Path,
        decode: bool,
        maximum: u64,
        max_body: u64,
    ) -> Result<Self, CliError> {
        Ok(Self {
            staged: StagedDirectory::stage(destination)?,
            destination: destination.to_owned(),
            pending: BTreeMap::new(),
            decode,
            maximum,
            written: 0,
            max_body,
        })
    }

    fn start(&self, key: Key) -> Result<Pending, CliError> {
        let path = self
            .staged
            .path()
            .join(format!("tcp-{}-{}-{}.partial", key.0, key.1, key.2));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(|error| CliError::caused(Kind::Io, &error))?;
        Ok(Pending {
            file,
            path,
            bytes: 0,
        })
    }

    pub(super) fn chunk(
        &mut self,
        stream: u64,
        generation: u64,
        index: u64,
        bytes: &[u8],
    ) -> Result<(), CliError> {
        crate::cancellation::check()?;
        let next = self
            .written
            .checked_add(bytes.len() as u64)
            .filter(|next| *next <= self.maximum)
            .ok_or_else(|| CliError::new(Kind::Policy, "HTTP exported-byte limit exceeded"))?;
        let key = (stream, generation, index);
        if !self.pending.contains_key(&key) {
            let pending = self.start(key)?;
            self.pending.insert(key, pending);
        }
        let pending = self.pending.get_mut(&key).expect("started entity");
        pending
            .file
            .write_all(bytes)
            .map_err(|error| CliError::caused(Kind::Io, &error))?;
        pending.bytes += bytes.len() as u64;
        self.written = next;
        Ok(())
    }

    pub(super) fn message(&mut self, message: &Message) -> Result<Option<Entity>, CliError> {
        let key = (message.stream, message.generation, message.index);
        let pending = self.pending.remove(&key);
        if message.status != Status::Complete
            || !matches!(
                message.framing,
                Some(Body::Length(_) | Body::Chunked | Body::Close)
            )
        {
            if let Some(pending) = pending {
                drop(pending.file);
                std::fs::remove_file(pending.path)
                    .map_err(|error| CliError::caused(Kind::Io, &error))?;
            }
            return Ok(None);
        }
        let mut pending = match pending {
            Some(pending) => pending,
            None => self.start(key)?,
        };
        let direction = direction(&message.flow);
        let name = format!(
            "tcp-{}-{direction}-{}-{}.body",
            message.stream, message.generation, message.index
        );
        let path = self.staged.path().join(&name);
        pending
            .file
            .flush()
            .map_err(|error| CliError::caused(Kind::Io, &error))?;
        let encoding = message.head.as_ref().and_then(|head| {
            let encodings: Vec<_> = head
                .headers
                .iter()
                .filter(|header| header.name.eq_ignore_ascii_case("content-encoding"))
                .map(|header| {
                    String::from_utf8_lossy(&header.value)
                        .trim()
                        .to_ascii_lowercase()
                })
                .collect();
            (!encodings.is_empty()).then(|| encodings.join(", "))
        });
        let mut entity = Entity {
            path: self.destination.join(&name).display().to_string(),
            bytes: pending.bytes,
            decoded_path: None,
            decoded_bytes: None,
            content_encoding: encoding.clone(),
        };
        if self.decode
            && let Some(encoding) = encoding
            && matches!(encoding.as_str(), "gzip" | "x-gzip" | "deflate")
        {
            pending
                .file
                .seek(SeekFrom::Start(0))
                .map_err(|error| CliError::caused(Kind::Io, &error))?;
            let decoded_name = format!("{name}.decoded");
            let mut decoded = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.staged.path().join(&decoded_name))
                .map_err(|error| CliError::caused(Kind::Io, &error))?;
            let maximum = self.max_body.min(self.maximum.saturating_sub(self.written));
            let bytes = packetcraftr_core::analysis::http::decode_content(
                &mut pending.file,
                &mut decoded,
                &encoding,
                maximum,
            )
            .map_err(CliError::classified)?;
            decoded
                .flush()
                .map_err(|error| CliError::caused(Kind::Io, &error))?;
            self.written += bytes;
            entity.decoded_bytes = Some(bytes);
            entity.decoded_path = Some(self.destination.join(decoded_name).display().to_string());
        }
        drop(pending.file);
        std::fs::rename(pending.path, path).map_err(|error| CliError::caused(Kind::Io, &error))?;
        Ok(Some(entity))
    }

    pub(super) fn finish(mut self) -> Result<(), CliError> {
        for (_, pending) in std::mem::take(&mut self.pending) {
            drop(pending.file);
            std::fs::remove_file(pending.path)
                .map_err(|error| CliError::caused(Kind::Io, &error))?;
        }
        self.staged.persist()
    }
}

fn direction(flow: &ScopedFlowKey) -> &'static str {
    if (flow.flow.source, flow.flow.source_port)
        <= (flow.flow.destination, flow.flow.destination_port)
    {
        "a-to-b"
    } else {
        "b-to-a"
    }
}
