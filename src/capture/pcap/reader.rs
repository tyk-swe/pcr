enum ReaderState {
    Pcap {
        endianness: Endianness,
        precision: TimestampPrecision,
        snap_len: u32,
        link_type: LinkType,
    },
    PcapNg {
        endianness: Endianness,
        interfaces: Vec<Interface>,
        interface_base: u32,
    },
}

/// A streaming capture reader over any [`Read`] implementation.
///
/// Construction consumes only the container header.  Each call to
/// [`next_frame`](Self::next_frame) then reads at most one packet plus any
/// intervening metadata blocks.
pub struct Reader<R> {
    inner: R,
    state: ReaderState,
    interfaces: Vec<Interface>,
    max_size: usize,
    max_interfaces: usize,
    max_total_interfaces: usize,
    max_metadata_blocks_per_frame: usize,
    finished: bool,
}

impl<R: Read> Reader<R> {
    /// Opens a capture with the default 16 MiB packet/block limit.
    pub fn new(inner: R) -> Result<Self, Error> {
        Self::with_limit(inner, DEFAULT_SIZE_LIMIT)
    }

    /// Opens a capture with a caller-provided packet/block size limit.
    pub fn with_limit(inner: R, max_size: usize) -> Result<Self, Error> {
        Self::with_limits(inner, max_size, DEFAULT_INTERFACE_LIMIT)
    }

    /// Opens a capture with caller-provided packet/block and interface limits.
    pub fn with_limits(inner: R, max_size: usize, max_interfaces: usize) -> Result<Self, Error> {
        Self::with_resource_limits(
            inner,
            max_size,
            max_interfaces,
            DEFAULT_METADATA_BLOCK_LIMIT,
        )
    }

    pub fn with_resource_limits(
        inner: R,
        max_size: usize,
        max_interfaces: usize,
        max_metadata_blocks_per_frame: usize,
    ) -> Result<Self, Error> {
        Self::with_all_resource_limits(
            inner,
            max_size,
            max_interfaces,
            DEFAULT_TOTAL_INTERFACE_LIMIT,
            max_metadata_blocks_per_frame,
        )
    }

    /// Opens a capture with independent per-section and aggregate retained
    /// interface limits.
    pub fn with_all_resource_limits(
        mut inner: R,
        max_size: usize,
        max_interfaces: usize,
        max_total_interfaces: usize,
        max_metadata_blocks_per_frame: usize,
    ) -> Result<Self, Error> {
        let mut magic = [0_u8; 4];
        if !read_exact_or_eof(&mut inner, &mut magic, "capture magic")? {
            return Err(Error::EmptyInput);
        }

        let state = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => read_pcap_header(
                &mut inner,
                Endianness::Little,
                TimestampPrecision::Microseconds,
            )?,
            [0xa1, 0xb2, 0xc3, 0xd4] => read_pcap_header(
                &mut inner,
                Endianness::Big,
                TimestampPrecision::Microseconds,
            )?,
            [0x4d, 0x3c, 0xb2, 0xa1] => read_pcap_header(
                &mut inner,
                Endianness::Little,
                TimestampPrecision::Nanoseconds,
            )?,
            [0xa1, 0xb2, 0x3c, 0x4d] => {
                read_pcap_header(&mut inner, Endianness::Big, TimestampPrecision::Nanoseconds)?
            }
            PCAPNG_SECTION_HEADER => {
                let endianness = read_section_header_after_type(&mut inner, max_size)?;
                ReaderState::PcapNg {
                    endianness,
                    interfaces: Vec::new(),
                    interface_base: 0,
                }
            }
            unknown_magic => {
                return Err(Error::UnrecognizedFormat {
                    magic: unknown_magic,
                });
            }
        };

        let interfaces = match &state {
            ReaderState::Pcap {
                precision,
                snap_len,
                link_type,
                ..
            } => vec![Interface {
                link_type: *link_type,
                snap_len: *snap_len,
                timestamp_resolution: match precision {
                    TimestampPrecision::Microseconds => TimestampResolution::Decimal(6),
                    TimestampPrecision::Nanoseconds => TimestampResolution::Decimal(9),
                },
                timestamp_offset: 0,
            }],
            ReaderState::PcapNg { .. } => Vec::new(),
        };
        if interfaces.len() > max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: max_total_interfaces,
            });
        }

        Ok(Self {
            inner,
            state,
            interfaces,
            max_size,
            max_interfaces,
            max_total_interfaces,
            max_metadata_blocks_per_frame,
            finished: false,
        })
    }

    /// Returns the detected capture format.
    pub fn format(&self) -> Format {
        match self.state {
            ReaderState::Pcap { .. } => Format::Pcap,
            ReaderState::PcapNg { .. } => Format::PcapNg,
        }
    }

    /// Returns the capture byte order.
    pub fn endianness(&self) -> Endianness {
        match self.state {
            ReaderState::Pcap { endianness, .. } | ReaderState::PcapNg { endianness, .. } => {
                endianness
            }
        }
    }

    /// Returns the configured packet/block limit.
    pub fn size_limit(&self) -> usize {
        self.max_size
    }

    /// Interface metadata parsed so far.
    ///
    /// Classic PCAP exposes its single global interface immediately. PCAPNG
    /// descriptions are appended while [`next_frame`](Self::next_frame)
    /// advances the stream, before any frame that references them is returned.
    pub fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    /// Reads the next frame, or `None` after a clean end of file.
    pub fn next_frame(&mut self) -> Result<Option<Frame>, Error> {
        if self.finished {
            return Ok(None);
        }

        let result = match &mut self.state {
            ReaderState::Pcap {
                endianness,
                precision,
                snap_len,
                link_type,
            } => read_next_pcap_frame(
                &mut self.inner,
                *endianness,
                *precision,
                *snap_len,
                *link_type,
                self.max_size,
            ),
            ReaderState::PcapNg { .. } => self.next_pcapng_frame(),
        };

        match result {
            Ok(frame) => {
                if frame.is_none() {
                    self.finished = true;
                }
                Ok(frame)
            }
            Err(error) => {
                self.finished = true;
                Err(error)
            }
        }
    }

    /// Alias for [`next_frame`](Self::next_frame).
    pub fn read_frame(&mut self) -> Result<Option<Frame>, Error> {
        self.next_frame()
    }

    fn next_pcapng_frame(&mut self) -> Result<Option<Frame>, Error> {
        let mut metadata_blocks = 0usize;
        loop {
            let (section_endianness, section_interfaces, section_interface_base) = match &self.state
            {
                ReaderState::PcapNg {
                    endianness,
                    interfaces,
                    interface_base,
                } => (*endianness, interfaces, *interface_base),
                ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
            };

            let Some(raw_header) = read_pcapng_block_header(&mut self.inner)? else {
                return Ok(None);
            };

            if raw_header[..4] == PCAPNG_SECTION_HEADER {
                metadata_blocks = metadata_blocks.saturating_add(1);
                if metadata_blocks > self.max_metadata_blocks_per_frame {
                    return Err(Error::MetadataBlockLimit {
                        limit: self.max_metadata_blocks_per_frame,
                    });
                }
                let new_endianness = read_section_header_with_length(
                    &mut self.inner,
                    raw_header[4..8].try_into().expect("four-byte slice"),
                    self.max_size,
                )?;
                match &mut self.state {
                    ReaderState::PcapNg {
                        endianness,
                        interfaces,
                        interface_base,
                    } => {
                        *interface_base = interface_base
                            .checked_add(u32::try_from(interfaces.len()).map_err(|_| {
                                Error::InterfaceLimit {
                                    limit: self.max_interfaces,
                                }
                            })?)
                            .ok_or(Error::InterfaceLimit {
                                limit: self.max_interfaces,
                            })?;
                        *endianness = new_endianness;
                        interfaces.clear();
                    }
                    ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                }
                continue;
            }

            let block_type = decode_u32(section_endianness, &raw_header[..4]);
            let block_length = decode_u32(section_endianness, &raw_header[4..8]);
            validate_pcapng_block_length(block_length, self.max_size)?;
            let remaining =
                usize::try_from(block_length).map_err(|_| Error::InvalidBlockLength {
                    length: block_length,
                })? - 8;
            let mut block = vec![0_u8; remaining];
            read_exact_counted(&mut self.inner, &mut block, "pcapng block")?;

            let body_length = block.len() - 4;
            let trailing_length = decode_u32(section_endianness, &block[body_length..]);
            if trailing_length != block_length {
                return Err(Error::BlockLengthMismatch {
                    leading: block_length,
                    trailing: trailing_length,
                });
            }
            let body = &block[..body_length];

            if !matches!(
                block_type,
                PCAPNG_ENHANCED_PACKET_BLOCK | PCAPNG_PACKET_BLOCK | PCAPNG_SIMPLE_PACKET_BLOCK
            ) {
                metadata_blocks = metadata_blocks.saturating_add(1);
                if metadata_blocks > self.max_metadata_blocks_per_frame {
                    return Err(Error::MetadataBlockLimit {
                        limit: self.max_metadata_blocks_per_frame,
                    });
                }
            }

            match block_type {
                PCAPNG_INTERFACE_DESCRIPTION_BLOCK => {
                    let description = parse_interface_description(body, section_endianness)?;
                    match &mut self.state {
                        ReaderState::PcapNg { interfaces, .. } => {
                            if interfaces.len() >= self.max_interfaces {
                                return Err(Error::InterfaceLimit {
                                    limit: self.max_interfaces,
                                });
                            }
                            if self.interfaces.len() >= self.max_total_interfaces {
                                return Err(Error::TotalInterfaceLimit {
                                    limit: self.max_total_interfaces,
                                });
                            }
                            interfaces.push(description);
                            self.interfaces.push(description);
                        }
                        ReaderState::Pcap { .. } => unreachable!("state checked by caller"),
                    }
                }
                PCAPNG_ENHANCED_PACKET_BLOCK => {
                    return parse_enhanced_packet(
                        body,
                        section_endianness,
                        section_interfaces,
                        section_interface_base,
                        self.max_size,
                    )
                    .map(Some);
                }
                PCAPNG_PACKET_BLOCK => {
                    return parse_obsolete_packet(
                        body,
                        section_endianness,
                        section_interfaces,
                        section_interface_base,
                        self.max_size,
                    )
                    .map(Some);
                }
                PCAPNG_SIMPLE_PACKET_BLOCK => {
                    return parse_simple_packet(
                        body,
                        section_endianness,
                        section_interfaces,
                        section_interface_base,
                        self.max_size,
                    )
                    .map(Some);
                }
                _ => {
                    // Metadata and extension blocks are length-delimited, so an
                    // unknown block can be skipped without guessing its layout.
                }
            }
        }
    }

    pub fn get_ref(&self) -> &R {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }

    pub fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Iterator for Reader<R> {
    type Item = Result<Frame, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.next_frame() {
            Ok(Some(frame)) => Some(Ok(frame)),
            Ok(None) => None,
            Err(error) => {
                self.finished = true;
                Some(Err(error))
            }
        }
    }
}
