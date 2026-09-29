// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

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

pub const MIN_WINDOW_LOG: u32 = 10;
/// Largest accepted [`Limits::max_window_log`], a 64 MiB decoding window.
pub const MAX_WINDOW_LOG: u32 = 26;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Encoded source bytes, bounding empty members and Zstd skippable frames.
    pub max_encoded_bytes: u64,
    pub max_decoded_bytes: u64,
    /// Base-two logarithm of the maximum Zstd window.
    pub max_window_log: u32,
}
impl Limits {
    pub fn validate(&self) -> Result<(), Error> {
        if !(MIN_WINDOW_LOG..=MAX_WINDOW_LOG).contains(&self.max_window_log) {
            return Err(Error::WindowLimit {
                value: self.max_window_log,
            });
        }
        Ok(())
    }
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            max_encoded_bytes: super::DEFAULT_MAX_STREAM_BYTES,
            max_decoded_bytes: super::DEFAULT_MAX_STREAM_BYTES,
            max_window_log: MAX_WINDOW_LOG,
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
    #[error("{format:?} capture compression I/O failed")]
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

type Source<R> = BufReader<io::Chain<Cursor<Vec<u8>>, Bounded<R>>>;

struct Bounded<R> {
    inner: R,
    remaining: u64,
    limit: u64,
    exceeded: bool,
    error: fn(u64) -> Error,
}
impl<R> Bounded<R> {
    fn new(inner: R, limit: u64, error: fn(u64) -> Error) -> Self {
        Self {
            inner,
            remaining: limit,
            limit,
            exceeded: false,
            error,
        }
    }
    fn limit_error(&self) -> io::Error {
        io::Error::other((self.error)(self.limit))
    }
}
impl<R: Read> Read for Bounded<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if self.exceeded {
            return Err(self.limit_error());
        }
        if self.remaining == 0 {
            if self.inner.read(&mut [0u8; 1])? == 0 {
                return Ok(0);
            }
            self.exceeded = true;
            return Err(self.limit_error());
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
impl<R: Read> Decoder<R> {
    fn format(&self) -> Format {
        match self {
            Self::Plain(_) => Format::None,
            Self::Gzip(_) => Format::Gzip,
            Self::Zstd(_) => Format::Zstd,
        }
    }
}
impl<R: Read> Read for Decoder<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let format = self.format();
        match self {
            Self::Plain(reader) => reader.read(output),
            Self::Gzip(reader) => reader.read(output),
            Self::Zstd(reader) => reader.read(output),
        }
        .map_err(|source| io::Error::other(Error::Io { format, source }))
    }
}

pub struct Input<R: Read> {
    reader: Bounded<Decoder<R>>,
}
impl<R: Read> Input<R> {
    pub fn new(source: R, limits: Limits) -> Result<Self, Error> {
        limits.validate()?;
        let mut source = Bounded::new(source, limits.max_encoded_bytes, |limit| {
            Error::EncodedByteLimit { limit }
        });
        let mut prefix = Vec::with_capacity(4);
        (&mut source)
            .take(4)
            .read_to_end(&mut prefix)
            .map_err(|source| Error::Io {
                format: Format::None,
                source,
            })?;
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
            reader: Bounded::new(decoder, limits.max_decoded_bytes, |limit| {
                Error::ByteLimit { limit }
            }),
        })
    }
    pub fn format(&self) -> Format {
        self.reader.inner.format()
    }
}
impl<R: Read> Read for Input<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.reader.read(output)
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
