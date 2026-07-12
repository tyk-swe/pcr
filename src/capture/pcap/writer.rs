enum WriterState {
    Pcap {
        endianness: Endianness,
        precision: TimestampPrecision,
        snap_len: u32,
        link_type: LinkType,
    },
    PcapNg {
        endianness: Endianness,
        interfaces: Vec<InterfaceDescription>,
    },
}

#[derive(Clone, Copy, Debug)]
struct InterfacePlan {
    id: u32,
    description: InterfaceDescription,
    needs_commit: bool,
}

/// A streaming capture writer over any [`Write`] implementation.
pub struct Writer<W> {
    inner: W,
    state: WriterState,
    max_size: usize,
    max_interfaces: usize,
    stream_limits: Limits,
    frames_written: u64,
    captured_bytes_written: u64,
}

impl<W: Write> Writer<W> {
    /// Creates a writer with a default interface and the 16 MiB size limit.
    ///
    /// A PCAPNG writer created this way starts with interface zero.  Use
    /// [`pcapng`](Self::pcapng) followed by [`add_interface`](Self::add_interface)
    /// when all interface descriptions need to be declared explicitly.
    pub fn new(inner: W, format: Format, link_type: LinkType) -> Result<Self, Error> {
        Self::with_limit(inner, format, link_type, DEFAULT_SIZE_LIMIT)
    }

    /// Creates a writer with a default interface and a caller-provided limit.
    pub fn with_limit(
        inner: W,
        format: Format,
        link_type: LinkType,
        max_size: usize,
    ) -> Result<Self, Error> {
        Self::with_limits(inner, format, link_type, max_size, DEFAULT_INTERFACE_LIMIT)
    }

    /// Creates a writer with caller-provided packet/block and PCAPNG
    /// interface limits.
    pub fn with_limits(
        inner: W,
        format: Format,
        link_type: LinkType,
        max_size: usize,
        max_interfaces: usize,
    ) -> Result<Self, Error> {
        match format {
            Format::Pcap => {
                Self::pcap_with_options(inner, link_type, Endianness::Little, max_size, max_size)
            }
            Format::PcapNg => {
                let mut writer = Self::pcapng_with_resource_limits(
                    inner,
                    Endianness::Little,
                    max_size,
                    max_interfaces,
                )?;
                writer.add_interface_with_snaplen(link_type, usize_to_u32_limit(max_size)?)?;
                Ok(writer)
            }
        }
    }

    /// Creates a little-endian, nanosecond-resolution classic PCAP writer.
    pub fn pcap(inner: W, link_type: LinkType) -> Result<Self, Error> {
        Self::pcap_with_endianness(inner, link_type, Endianness::Little)
    }

    /// Creates a nanosecond-resolution classic PCAP writer.
    pub fn pcap_with_endianness(
        inner: W,
        link_type: LinkType,
        endianness: Endianness,
    ) -> Result<Self, Error> {
        Self::pcap_with_options(
            inner,
            link_type,
            endianness,
            DEFAULT_SIZE_LIMIT,
            DEFAULT_SIZE_LIMIT,
        )
    }

    /// Creates a classic PCAP writer with explicit byte order, snap length,
    /// and packet limit.
    pub fn pcap_with_options(
        inner: W,
        link_type: LinkType,
        endianness: Endianness,
        snap_len: usize,
        max_size: usize,
    ) -> Result<Self, Error> {
        Self::pcap_with_metadata(
            inner,
            link_type,
            endianness,
            TimestampResolution::Decimal(9),
            snap_len,
            max_size,
        )
    }

    /// Creates a classic PCAP writer with explicit byte order, timestamp
    /// resolution, snap length, and packet limit.
    pub fn pcap_with_metadata(
        mut inner: W,
        link_type: LinkType,
        endianness: Endianness,
        timestamp_resolution: TimestampResolution,
        snap_len: usize,
        max_size: usize,
    ) -> Result<Self, Error> {
        if link_type.0 > u16::MAX as u32 {
            return Err(Error::LinkTypeOutOfRange {
                link_type: link_type.0,
            });
        }
        let precision = match timestamp_resolution {
            TimestampResolution::Decimal(6) => TimestampPrecision::Microseconds,
            TimestampResolution::Decimal(9) => TimestampPrecision::Nanoseconds,
            TimestampResolution::Decimal(exponent) => {
                return Err(Error::InvalidTimestampResolution { base: 10, exponent });
            }
            TimestampResolution::Binary(exponent) => {
                return Err(Error::InvalidTimestampResolution { base: 2, exponent });
            }
        };
        let snap_len = usize_to_u32_limit(snap_len)?;
        if snap_len == 0 {
            return Err(Error::InvalidData {
                format: Format::Pcap,
                reason: "snapshot length must be non-zero",
            });
        }
        write_pcap_header(&mut inner, endianness, precision, snap_len, link_type)?;
        Ok(Self {
            inner,
            state: WriterState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            },
            max_size,
            max_interfaces: DEFAULT_INTERFACE_LIMIT,
            stream_limits: Limits::default(),
            frames_written: 0,
            captured_bytes_written: 0,
        })
    }

    /// Creates a little-endian PCAPNG writer without an interface block.
    pub fn pcapng(inner: W) -> Result<Self, Error> {
        Self::pcapng_with_endianness(inner, Endianness::Little)
    }

    /// Creates a PCAPNG writer without an interface block.
    pub fn pcapng_with_endianness(inner: W, endianness: Endianness) -> Result<Self, Error> {
        Self::pcapng_with_options(inner, endianness, DEFAULT_SIZE_LIMIT)
    }

    /// Creates a PCAPNG writer with explicit byte order and block limit.
    pub fn pcapng_with_options(
        inner: W,
        endianness: Endianness,
        max_size: usize,
    ) -> Result<Self, Error> {
        Self::pcapng_with_resource_limits(inner, endianness, max_size, DEFAULT_INTERFACE_LIMIT)
    }

    /// Creates a PCAPNG writer with explicit byte-order, block-size, and
    /// per-stream interface limits.
    pub fn pcapng_with_resource_limits(
        mut inner: W,
        endianness: Endianness,
        max_size: usize,
        max_interfaces: usize,
    ) -> Result<Self, Error> {
        if max_size < 28 {
            return Err(Error::SizeLimitExceeded {
                kind: "pcapng section header",
                declared: 28,
                limit: max_size,
            });
        }
        write_section_header(&mut inner, endianness)?;
        Ok(Self {
            inner,
            state: WriterState::PcapNg {
                endianness,
                interfaces: Vec::new(),
            },
            max_size,
            max_interfaces,
            stream_limits: Limits::default(),
            frames_written: 0,
            captured_bytes_written: 0,
        })
    }

    pub fn format(&self) -> Format {
        match self.state {
            WriterState::Pcap { .. } => Format::Pcap,
            WriterState::PcapNg { .. } => Format::PcapNg,
        }
    }

    pub fn endianness(&self) -> Endianness {
        match self.state {
            WriterState::Pcap { endianness, .. } | WriterState::PcapNg { endianness, .. } => {
                endianness
            }
        }
    }

    pub fn size_limit(&self) -> usize {
        self.max_size
    }

    /// Returns the configured PCAPNG interface limit.
    pub fn interface_limit(&self) -> usize {
        self.max_interfaces
    }

    /// Applies aggregate frame and captured-payload limits to future writes.
    ///
    /// Lowering a limit below already committed output is rejected without
    /// changing the writer configuration.
    pub fn set_stream_limits(&mut self, limits: Limits) -> Result<(), Error> {
        if self.frames_written > limits.max_frames {
            return Err(Error::FrameLimitExceeded {
                actual: self.frames_written,
                limit: limits.max_frames,
            });
        }
        if self.captured_bytes_written > limits.max_bytes {
            return Err(Error::StreamByteLimitExceeded {
                actual: self.captured_bytes_written,
                limit: limits.max_bytes,
            });
        }
        self.stream_limits = limits;
        Ok(())
    }

    pub fn stream_limits(&self) -> Limits {
        self.stream_limits
    }

    pub fn frames_written(&self) -> u64 {
        self.frames_written
    }

    pub fn captured_bytes_written(&self) -> u64 {
        self.captured_bytes_written
    }

    /// Adds a PCAPNG interface using the writer's configured size limit as
    /// its snap length and returns its numeric interface ID.
    pub fn add_interface(&mut self, link_type: LinkType) -> Result<u32, Error> {
        let snap_len = usize_to_u32_limit(self.max_size)?;
        self.add_interface_with_snaplen(link_type, snap_len)
    }

    /// Adds a PCAPNG interface with a signed timestamp offset in seconds.
    ///
    /// PCAPNG packet timestamps are unsigned counters relative to the
    /// interface's `if_tsoffset`.  Choose an offset no later than the earliest
    /// frame that will use this interface to represent pre-Unix-epoch times.
    /// An offset of zero produces the same interface block as
    /// [`add_interface`](Self::add_interface).
    pub fn add_interface_with_timestamp_offset(
        &mut self,
        link_type: LinkType,
        timestamp_offset: i64,
    ) -> Result<u32, Error> {
        let snap_len = usize_to_u32_limit(self.max_size)?;
        self.add_interface_with_snaplen_and_timestamp_offset(link_type, snap_len, timestamp_offset)
    }

    /// Adds a PCAPNG interface with an explicit snap length.
    pub fn add_interface_with_snaplen(
        &mut self,
        link_type: LinkType,
        snap_len: u32,
    ) -> Result<u32, Error> {
        self.add_interface_with_snaplen_and_timestamp_offset(link_type, snap_len, 0)
    }

    /// Adds a PCAPNG interface with an explicit snap length and signed
    /// timestamp offset in seconds.
    pub fn add_interface_with_snaplen_and_timestamp_offset(
        &mut self,
        link_type: LinkType,
        snap_len: u32,
        timestamp_offset: i64,
    ) -> Result<u32, Error> {
        self.add_interface_description(Interface {
            link_type,
            snap_len,
            timestamp_resolution: WRITER_TIMESTAMP_RESOLUTION,
            timestamp_offset,
        })
    }

    /// Adds one PCAPNG interface while retaining its timestamp metadata.
    pub fn add_interface_description(&mut self, description: Interface) -> Result<u32, Error> {
        let (endianness, interface_id) = self.validate_new_interface(description)?;

        write_interface_description(
            &mut self.inner,
            endianness,
            description.link_type,
            description.snap_len,
            description.timestamp_resolution,
            description.timestamp_offset,
        )?;
        match &mut self.state {
            WriterState::PcapNg { interfaces, .. } => {
                interfaces.push(description);
            }
            WriterState::Pcap { .. } => unreachable!("format checked above"),
        }
        Ok(interface_id)
    }

    fn validate_new_interface(
        &self,
        description: InterfaceDescription,
    ) -> Result<(Endianness, u32), Error> {
        validate_timestamp_resolution(description.timestamp_resolution)?;
        let block_length = if description.timestamp_offset == 0 {
            32
        } else {
            44
        };
        if self.max_size < block_length {
            return Err(Error::SizeLimitExceeded {
                kind: "pcapng interface description",
                declared: block_length as u64,
                limit: self.max_size,
            });
        }
        let (endianness, interface_id) = match &self.state {
            WriterState::Pcap { .. } => {
                return Err(Error::WrongWriterFormat {
                    expected: Format::PcapNg,
                    actual: Format::Pcap,
                });
            }
            WriterState::PcapNg {
                endianness,
                interfaces,
            } => {
                let next_count = interfaces
                    .len()
                    .checked_add(1)
                    .ok_or(Error::InterfaceLimit {
                        limit: self.max_interfaces,
                    })?;
                if next_count > self.max_interfaces {
                    return Err(Error::InterfaceLimit {
                        limit: self.max_interfaces,
                    });
                }
                (
                    *endianness,
                    u32::try_from(interfaces.len()).map_err(|_| Error::InterfaceLimit {
                        limit: self.max_interfaces.min(u32::MAX as usize),
                    })?,
                )
            }
        };

        if description.link_type.0 > u16::MAX as u32 {
            return Err(Error::LinkTypeOutOfRange {
                link_type: description.link_type.0,
            });
        }

        Ok((endianness, interface_id))
    }

    /// Writes one frame, validating all representability and length invariants
    /// before emitting any bytes for it.
    pub fn write_frame(&mut self, frame: &Frame) -> Result<(), Error> {
        validate_frame_lengths(frame, self.max_size)?;

        let next_frames = self
            .frames_written
            .checked_add(1)
            .ok_or(Error::FrameLimitExceeded {
                actual: u64::MAX,
                limit: self.stream_limits.max_frames,
            })?;
        if next_frames > self.stream_limits.max_frames {
            return Err(Error::FrameLimitExceeded {
                actual: next_frames,
                limit: self.stream_limits.max_frames,
            });
        }
        let next_bytes = self
            .captured_bytes_written
            .checked_add(u64::from(frame.captured_length))
            .ok_or(Error::StreamByteLimitExceeded {
                actual: u64::MAX,
                limit: self.stream_limits.max_bytes,
            })?;
        if next_bytes > self.stream_limits.max_bytes {
            return Err(Error::StreamByteLimitExceeded {
                actual: next_bytes,
                limit: self.stream_limits.max_bytes,
            });
        }

        match &self.state {
            WriterState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            } => {
                let endianness = *endianness;
                let precision = *precision;
                let snap_len = *snap_len;
                let link_type = *link_type;
                self.write_pcap_frame(frame, endianness, precision, snap_len, link_type)
            }
            WriterState::PcapNg { .. } => self.write_pcapng_frame(frame),
        }?;
        self.frames_written = next_frames;
        self.captured_bytes_written = next_bytes;
        Ok(())
    }

    /// Alias for [`write_frame`](Self::write_frame).
    pub fn write(&mut self, frame: &Frame) -> Result<(), Error> {
        self.write_frame(frame)
    }

    fn write_pcap_frame(
        &mut self,
        frame: &Frame,
        endianness: Endianness,
        precision: TimestampPrecision,
        snap_len: u32,
        link_type: LinkType,
    ) -> Result<(), Error> {
        if frame.interface.is_some() {
            return Err(Error::MetadataNotRepresentable {
                format: Format::Pcap,
                field: "interface",
            });
        }
        if frame.direction.is_some() {
            return Err(Error::MetadataNotRepresentable {
                format: Format::Pcap,
                field: "direction",
            });
        }
        if frame.link_type != link_type {
            return Err(Error::InterfaceLinkTypeMismatch {
                interface: 0,
                expected: link_type.0,
                actual: frame.link_type.0,
            });
        }
        if snap_len != 0 && frame.captured_length > snap_len {
            return Err(Error::SizeLimitExceeded {
                kind: "pcap captured packet",
                declared: u64::from(frame.captured_length),
                limit: snap_len as usize,
            });
        }

        let elapsed =
            frame
                .timestamp
                .duration_since(UNIX_EPOCH)
                .map_err(|_| Error::TimestampOutOfRange {
                    format: Format::Pcap,
                })?;
        let seconds = u32::try_from(elapsed.as_secs()).map_err(|_| Error::TimestampOutOfRange {
            format: Format::Pcap,
        })?;

        let fraction = match precision {
            TimestampPrecision::Microseconds if !elapsed.subsec_nanos().is_multiple_of(1_000) => {
                return Err(Error::MetadataNotRepresentable {
                    format: Format::Pcap,
                    field: "microsecond timestamp precision",
                });
            }
            TimestampPrecision::Microseconds => elapsed.subsec_micros(),
            TimestampPrecision::Nanoseconds => elapsed.subsec_nanos(),
        };

        write_u32(&mut self.inner, endianness, seconds)?;
        write_u32(&mut self.inner, endianness, fraction)?;
        write_u32(&mut self.inner, endianness, frame.captured_length)?;
        write_u32(&mut self.inner, endianness, frame.original_length)?;
        self.inner.write_all(&frame.bytes)?;
        Ok(())
    }

    fn write_pcapng_frame(&mut self, frame: &Frame) -> Result<(), Error> {
        let plan = self.select_interface(frame)?;
        let interface_id = plan.id;
        let interface = plan.description;
        let endianness = self.endianness();

        if interface.snap_len != 0 && frame.captured_length > interface.snap_len {
            return Err(Error::SizeLimitExceeded {
                kind: "pcapng captured packet",
                declared: u64::from(frame.captured_length),
                limit: interface.snap_len as usize,
            });
        }

        let timestamp = timestamp_to_ticks(
            frame.timestamp,
            interface.timestamp_resolution,
            interface.timestamp_offset,
        )?;
        let padded_packet_length = align_to_u32(frame.captured_length)?;
        let option_length = if frame.direction.is_some() { 12_u32 } else { 0 };
        let block_length = 32_u32
            .checked_add(padded_packet_length)
            .and_then(|length| length.checked_add(option_length))
            .ok_or(Error::InvalidBlockLength { length: u32::MAX })?;
        if block_length as usize > self.max_size {
            return Err(Error::SizeLimitExceeded {
                kind: "pcapng enhanced packet block",
                declared: u64::from(block_length),
                limit: self.max_size,
            });
        }

        if plan.needs_commit {
            let committed = self.add_interface_description(interface)?;
            debug_assert_eq!(committed, interface_id);
        }

        write_u32(&mut self.inner, endianness, PCAPNG_ENHANCED_PACKET_BLOCK)?;
        write_u32(&mut self.inner, endianness, block_length)?;
        write_u32(&mut self.inner, endianness, interface_id)?;
        write_u32(&mut self.inner, endianness, (timestamp >> 32) as u32)?;
        write_u32(&mut self.inner, endianness, timestamp as u32)?;
        write_u32(&mut self.inner, endianness, frame.captured_length)?;
        write_u32(&mut self.inner, endianness, frame.original_length)?;
        self.inner.write_all(&frame.bytes)?;
        write_padding(&mut self.inner, frame.captured_length)?;

        if let Some(direction) = frame.direction {
            write_u16(&mut self.inner, endianness, PCAPNG_OPTION_EPB_FLAGS)?;
            write_u16(&mut self.inner, endianness, 4)?;
            let flags = match direction {
                Direction::Unknown => 0,
                Direction::Inbound => 1,
                Direction::Outbound => 2,
            };
            write_u32(&mut self.inner, endianness, flags)?;
            write_u16(&mut self.inner, endianness, PCAPNG_OPTION_END)?;
            write_u16(&mut self.inner, endianness, 0)?;
        }
        write_u32(&mut self.inner, endianness, block_length)?;
        Ok(())
    }

    fn select_interface(&self, frame: &Frame) -> Result<InterfacePlan, Error> {
        if let Some(interface_id) = frame.interface {
            let interfaces = match &self.state {
                WriterState::PcapNg { interfaces, .. } => interfaces,
                WriterState::Pcap { .. } => unreachable!("format checked by caller"),
            };
            let interface =
                interfaces
                    .get(interface_id as usize)
                    .ok_or(Error::UndefinedInterface {
                        interface: interface_id,
                        available: interfaces.len(),
                    })?;
            if interface.link_type != frame.link_type {
                return Err(Error::InterfaceLinkTypeMismatch {
                    interface: interface_id,
                    expected: interface.link_type.0,
                    actual: frame.link_type.0,
                });
            }
            return Ok(InterfacePlan {
                id: interface_id,
                description: *interface,
                needs_commit: false,
            });
        }

        let matches = match &self.state {
            WriterState::PcapNg { interfaces, .. } => interfaces
                .iter()
                .enumerate()
                .filter(|(_, interface)| interface.link_type == frame.link_type)
                .map(|(index, _)| index as u32)
                .collect::<Vec<_>>(),
            WriterState::Pcap { .. } => unreachable!("format checked by caller"),
        };

        match matches.as_slice() {
            [interface_id] => {
                let description = match &self.state {
                    WriterState::PcapNg { interfaces, .. } => {
                        interfaces[*interface_id as usize]
                    }
                    WriterState::Pcap { .. } => unreachable!("format checked by caller"),
                };
                Ok(InterfacePlan {
                    id: *interface_id,
                    description,
                    needs_commit: false,
                })
            }
            [] => {
                let description = Interface {
                    link_type: frame.link_type,
                    snap_len: usize_to_u32_limit(self.max_size)?,
                    timestamp_resolution: WRITER_TIMESTAMP_RESOLUTION,
                    timestamp_offset: 0,
                };
                let (_, id) = self.validate_new_interface(description)?;
                Ok(InterfacePlan {
                    id,
                    description,
                    needs_commit: true,
                })
            }
            _ => Err(Error::AmbiguousInterface {
                link_type: frame.link_type.0,
            }),
        }
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        self.inner.flush().map_err(Error::from)
    }

    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }

    pub fn into_inner(self) -> W {
        self.inner
    }
}

/// Copies one capture stream into a bounded writer without retaining packet
/// payloads between records.
///
/// PCAPNG output normalizes multiple source sections into one section while
/// preserving the open link type, snap length, timestamp resolution/offset,
/// globalized interface identity, direction, captured length, original wire
/// length, and complete captured bytes. Classic PCAP can only be copied from
/// classic PCAP because its container cannot represent PCAPNG interfaces or
/// packet directions.
fn write_pcap_header<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    precision: TimestampPrecision,
    snap_len: u32,
    link_type: LinkType,
) -> Result<(), Error> {
    let magic = match (endianness, precision) {
        (Endianness::Little, TimestampPrecision::Microseconds) => [0xd4, 0xc3, 0xb2, 0xa1],
        (Endianness::Big, TimestampPrecision::Microseconds) => [0xa1, 0xb2, 0xc3, 0xd4],
        (Endianness::Little, TimestampPrecision::Nanoseconds) => [0x4d, 0x3c, 0xb2, 0xa1],
        (Endianness::Big, TimestampPrecision::Nanoseconds) => [0xa1, 0xb2, 0x3c, 0x4d],
    };
    writer.write_all(&magic)?;
    write_u16(writer, endianness, 2)?;
    write_u16(writer, endianness, 4)?;
    write_u32(writer, endianness, 0)?;
    write_u32(writer, endianness, 0)?;
    write_u32(writer, endianness, snap_len)?;
    write_u32(writer, endianness, link_type.0)?;
    Ok(())
}

fn write_section_header<W: Write>(writer: &mut W, endianness: Endianness) -> Result<(), Error> {
    write_u32(writer, endianness, PCAPNG_SECTION_HEADER_BLOCK)?;
    write_u32(writer, endianness, 28)?;
    write_u32(writer, endianness, PCAPNG_BYTE_ORDER_MAGIC)?;
    write_u16(writer, endianness, 1)?;
    write_u16(writer, endianness, 0)?;
    write_i64(writer, endianness, -1)?;
    write_u32(writer, endianness, 28)?;
    Ok(())
}

fn write_interface_description<W: Write>(
    writer: &mut W,
    endianness: Endianness,
    link_type: LinkType,
    snap_len: u32,
    timestamp_resolution: TimestampResolution,
    timestamp_offset: i64,
) -> Result<(), Error> {
    let block_length = if timestamp_offset == 0 { 32 } else { 44 };
    write_u32(writer, endianness, PCAPNG_INTERFACE_DESCRIPTION_BLOCK)?;
    write_u32(writer, endianness, block_length)?;
    write_u16(writer, endianness, link_type.0 as u16)?;
    write_u16(writer, endianness, 0)?;
    write_u32(writer, endianness, snap_len)?;
    write_u16(writer, endianness, PCAPNG_OPTION_IF_TSRESOL)?;
    write_u16(writer, endianness, 1)?;
    let resolution = match timestamp_resolution {
        TimestampResolution::Decimal(exponent) if exponent <= 0x7f => exponent,
        TimestampResolution::Binary(exponent) if exponent <= 0x7f => exponent | 0x80,
        TimestampResolution::Decimal(exponent) => {
            return Err(Error::InvalidTimestampResolution { base: 10, exponent });
        }
        TimestampResolution::Binary(exponent) => {
            return Err(Error::InvalidTimestampResolution { base: 2, exponent });
        }
    };
    writer.write_all(&[resolution, 0, 0, 0])?;
    if timestamp_offset != 0 {
        write_u16(writer, endianness, PCAPNG_OPTION_IF_TSOFFSET)?;
        write_u16(writer, endianness, 8)?;
        write_i64(writer, endianness, timestamp_offset)?;
    }
    write_u16(writer, endianness, PCAPNG_OPTION_END)?;
    write_u16(writer, endianness, 0)?;
    write_u32(writer, endianness, block_length)?;
    Ok(())
}
