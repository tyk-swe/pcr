// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Streaming compression with explicit decoded-byte and window ceilings.

use crate::error::{Classification, Classified, Kind};
use serde::{Deserialize, Serialize};
use std::io::{self, BufReader, Cursor, Read, Write};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    #[default]
    None,
    Gzip,
    Zstd,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Encoded source bytes, bounding empty members and Zstd skippable frames.
    pub max_encoded_bytes: u64,
    /// All decoded container bytes, including headers and metadata.
    pub max_decoded_bytes: u64,
    /// Base-two logarithm of the maximum Zstd window; accepted range 10..=26.
    pub max_window_log: u32,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: super::DEFAULT_STREAM_BYTES,
            max_decoded_bytes: super::DEFAULT_STREAM_BYTES,
            max_window_log: 26,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("encoded capture exceeds {limit} bytes")]
    EncodedByteLimit { limit: u64 },
    #[error("decoded capture exceeds {limit} bytes")]
    ByteLimit { limit: u64 },
    #[error("Zstd window log {value} is outside 10..=26")]
    WindowLimit { value: u32 },
    #[error("{format:?} capture compression I/O failed: {source}")]
    Io {
        format: Format,
        #[source]
        source: io::Error,
    },
}
impl Classified for Error {
    fn classification(&self) -> Classification {
        match self {
            Self::ByteLimit { .. } | Self::EncodedByteLimit { .. } | Self::WindowLimit { .. } => {
                Classification::new(
                    "packet.capture_compression_limit",
                    Kind::Packet,
                    Some("choose a finite decoded-byte/window limit adequate for this capture"),
                )
            }
            Self::Io { source, .. }
                if source
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<Self>())
                    .is_some() =>
            {
                source
                    .get_ref()
                    .and_then(|source| source.downcast_ref::<Self>())
                    .expect("guarded compression source")
                    .classification()
            }
            Self::Io { .. } => Classification::new(
                "io.capture_compression",
                Kind::Io,
                Some("check the compressed capture and its storage source"),
            ),
        }
    }
}

type Source<R> = BufReader<io::Chain<Cursor<Vec<u8>>, EncodedInput<R>>>;

struct EncodedInput<R> {
    inner: R,
    remaining: u64,
    limit: u64,
    exceeded: bool,
}
impl<R: Read> Read for EncodedInput<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.exceeded {
            return Err(io::Error::other(Error::EncodedByteLimit {
                limit: self.limit,
            }));
        }
        if self.remaining == 0 {
            if self.inner.read(&mut [0u8; 1])? == 0 {
                return Ok(0);
            }
            self.exceeded = true;
            return Err(io::Error::other(Error::EncodedByteLimit {
                limit: self.limit,
            }));
        }
        let allowed = bytes
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.inner.read(&mut bytes[..allowed])?;
        if count > allowed {
            return Err(io::Error::other("reader exceeded its buffer"));
        }
        self.remaining -= count as u64;
        Ok(count)
    }
}
enum Decoder<R: Read> {
    Plain(Source<R>),
    Gzip(flate2::bufread::MultiGzDecoder<Source<R>>),
    Zstd(zstd::stream::read::Decoder<'static, Source<R>>),
}

pub struct Input<R: Read> {
    decoder: Decoder<R>,
    format: Format,
    remaining: u64,
    limit: u64,
    exceeded: bool,
}
impl<R: Read> Input<R> {
    /// Detects compression by magic without requiring seek or a file extension.
    pub fn new(source: R, limits: Limits) -> Result<Self, Error> {
        let mut source = EncodedInput {
            inner: source,
            remaining: limits.max_encoded_bytes,
            limit: limits.max_encoded_bytes,
            exceeded: false,
        };
        if !(10..=26).contains(&limits.max_window_log) {
            return Err(Error::WindowLimit {
                value: limits.max_window_log,
            });
        }
        let mut prefix = vec![0; 4];
        let mut filled = 0;
        while filled < prefix.len() {
            match source.read(&mut prefix[filled..]) {
                Ok(0) => break,
                Ok(n) if n <= prefix.len() - filled => filled += n,
                Ok(_) => {
                    return Err(Error::Io {
                        format: Format::None,
                        source: io::Error::other("reader exceeded prefix buffer"),
                    });
                }
                Err(source) if source.kind() == io::ErrorKind::Interrupted => continue,
                Err(source) => {
                    return Err(Error::Io {
                        format: Format::None,
                        source,
                    });
                }
            }
        }
        prefix.truncate(filled);
        let format = if prefix.starts_with(&[0x1f, 0x8b]) {
            Format::Gzip
        } else if prefix == [0x28, 0xb5, 0x2f, 0xfd]
            || (prefix.len() == 4 && prefix[0] & 0xf0 == 0x50 && prefix[1..] == [0x2a, 0x4d, 0x18])
        {
            Format::Zstd
        } else {
            Format::None
        };
        let source = BufReader::new(Cursor::new(prefix).chain(source));
        let decoder = match format {
            Format::None => Decoder::Plain(source),
            Format::Gzip => Decoder::Gzip(flate2::bufread::MultiGzDecoder::new(source)),
            Format::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::with_buffer(source)
                    .map_err(|source| Error::Io { format, source })?;
                decoder
                    .window_log_max(limits.max_window_log)
                    .map_err(|source| Error::Io { format, source })?;
                Decoder::Zstd(decoder)
            }
        };
        Ok(Self {
            decoder,
            format,
            remaining: limits.max_decoded_bytes,
            limit: limits.max_decoded_bytes,
            exceeded: false,
        })
    }
    pub fn format(&self) -> Format {
        self.format
    }
    fn read_inner(&mut self, output: &mut [u8]) -> io::Result<usize> {
        match &mut self.decoder {
            Decoder::Plain(reader) => reader.read(output),
            Decoder::Gzip(reader) => reader.read(output),
            Decoder::Zstd(reader) => reader.read(output),
        }
        .map_err(|source| {
            io::Error::other(Error::Io {
                format: self.format,
                source,
            })
        })
    }
}
impl<R: Read> Read for Input<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.exceeded {
            return Err(io::Error::other(Error::ByteLimit { limit: self.limit }));
        }
        if self.remaining == 0 {
            let count = self.read_inner(&mut [0u8; 1])?;
            if count == 0 {
                return Ok(0);
            }
            self.exceeded = true;
            return Err(io::Error::other(Error::ByteLimit { limit: self.limit }));
        }
        let allowed = output
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let count = self.read_inner(&mut output[..allowed])?;
        self.remaining = self
            .remaining
            .checked_sub(count as u64)
            .ok_or_else(|| io::Error::other("decoder exceeded its output buffer"))?;
        Ok(count)
    }
}

enum WriterState<W: Write> {
    Plain(W),
    Gzip(flate2::write::GzEncoder<W>),
    Zstd(zstd::stream::write::Encoder<'static, W>),
}

/// An owned capture encoder. Call `finish` before publishing completion.
pub struct Output<W: Write> {
    encoder: WriterState<W>,
    format: Format,
}
impl<W: Write> Output<W> {
    pub fn new(destination: W, format: Format) -> Result<Self, Error> {
        let encoder = match format {
            Format::None => WriterState::Plain(destination),
            Format::Gzip => WriterState::Gzip(flate2::write::GzEncoder::new(
                destination,
                flate2::Compression::default(),
            )),
            Format::Zstd => WriterState::Zstd(
                zstd::stream::write::Encoder::new(destination, 3)
                    .map_err(|source| Error::Io { format, source })?,
            ),
        };
        Ok(Self { encoder, format })
    }
    /// Finalizes checksums/trailers and flushes the underlying destination.
    pub fn finish(self) -> Result<W, Error> {
        let mut writer = match self.encoder {
            WriterState::Plain(writer) => Ok(writer),
            WriterState::Gzip(writer) => writer.finish(),
            WriterState::Zstd(writer) => writer.finish(),
        }
        .map_err(|source| Error::Io {
            format: self.format,
            source,
        })?;
        writer.flush().map_err(|source| Error::Io {
            format: self.format,
            source,
        })?;
        Ok(writer)
    }
}
impl<W: Write> Write for Output<W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        match &mut self.encoder {
            WriterState::Plain(writer) => writer.write(bytes),
            WriterState::Gzip(writer) => writer.write(bytes),
            WriterState::Zstd(writer) => writer.write(bytes),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match &mut self.encoder {
            WriterState::Plain(writer) => writer.flush(),
            WriterState::Gzip(writer) => writer.flush(),
            WriterState::Zstd(writer) => writer.flush(),
        }
    }
}
