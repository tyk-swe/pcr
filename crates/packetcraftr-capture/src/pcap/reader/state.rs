// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! PCAPNG reader state.

use super::super::{
    models::{Endianness, Error, Interface},
    pcapng::SectionHeader,
};

pub(in crate::pcap) struct PcapNgState {
    endianness: Endianness,
    interfaces: Vec<Interface>,
    interface_base: u32,
    remaining_in_section: Option<u64>,
}

impl PcapNgState {
    pub(super) fn new(header: SectionHeader) -> Self {
        Self {
            endianness: header.endianness,
            interfaces: Vec::new(),
            interface_base: 0,
            remaining_in_section: header.length,
        }
    }

    pub(super) fn endianness(&self) -> Endianness {
        self.endianness
    }

    pub(super) fn interfaces(&self) -> &[Interface] {
        &self.interfaces
    }

    pub(super) fn interface_base(&self) -> u32 {
        self.interface_base
    }

    pub(super) fn remaining_in_section(&self) -> Option<u64> {
        self.remaining_in_section
    }

    pub(super) fn start_section(
        &mut self,
        header: SectionHeader,
        max_interfaces: usize,
    ) -> Result<(), Error> {
        let section_interfaces =
            u32::try_from(self.interfaces.len()).map_err(|_| Error::InterfaceLimit {
                limit: max_interfaces,
            })?;
        let interface_base =
            self.interface_base
                .checked_add(section_interfaces)
                .ok_or(Error::InterfaceLimit {
                    limit: max_interfaces,
                })?;
        self.endianness = header.endianness;
        self.interfaces.clear();
        self.interface_base = interface_base;
        self.remaining_in_section = header.length;
        Ok(())
    }

    pub(super) fn commit_block(&mut self, block_length: u32) {
        if let Some(remaining) = &mut self.remaining_in_section {
            *remaining -= u64::from(block_length);
        }
    }

    pub(super) fn add_interface(
        &mut self,
        all_interfaces: &mut Vec<Interface>,
        description: Interface,
        max_interfaces: usize,
        max_total_interfaces: usize,
    ) -> Result<(), Error> {
        if self.interfaces.len() >= max_interfaces {
            return Err(Error::InterfaceLimit {
                limit: max_interfaces,
            });
        }
        if all_interfaces.len() >= max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: max_total_interfaces,
            });
        }
        self.interfaces.push(description);
        all_interfaces.push(description);
        Ok(())
    }
}
