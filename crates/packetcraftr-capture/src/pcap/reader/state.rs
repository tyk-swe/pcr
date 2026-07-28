// Copyright (C) 2026 tyk-swe
// SPDX-License-Identifier: AGPL-3.0-only

//! Transactional PCAPNG reader-state planning and application.

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

pub(super) struct SectionTransition {
    endianness: Endianness,
    interface_base: u32,
    remaining_in_section: Option<u64>,
}

pub(super) struct InterfaceTransition {
    description: Interface,
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

    pub(super) fn plan_section(
        &self,
        header: SectionHeader,
        max_interfaces: usize,
    ) -> Result<SectionTransition, Error> {
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
        Ok(SectionTransition {
            endianness: header.endianness,
            interface_base,
            remaining_in_section: header.length,
        })
    }

    pub(super) fn apply_section(&mut self, transition: SectionTransition) {
        self.endianness = transition.endianness;
        self.interfaces.clear();
        self.interface_base = transition.interface_base;
        self.remaining_in_section = transition.remaining_in_section;
    }

    pub(super) fn commit_block(&mut self, block_length: u32) {
        if let Some(remaining) = &mut self.remaining_in_section {
            *remaining -= u64::from(block_length);
        }
    }

    pub(super) fn plan_interface(
        &self,
        description: Interface,
        total_interfaces: usize,
        max_interfaces: usize,
        max_total_interfaces: usize,
    ) -> Result<InterfaceTransition, Error> {
        if self.interfaces.len() >= max_interfaces {
            return Err(Error::InterfaceLimit {
                limit: max_interfaces,
            });
        }
        if total_interfaces >= max_total_interfaces {
            return Err(Error::TotalInterfaceLimit {
                limit: max_total_interfaces,
            });
        }
        Ok(InterfaceTransition { description })
    }

    pub(super) fn apply_interface(
        &mut self,
        all_interfaces: &mut Vec<Interface>,
        transition: InterfaceTransition,
    ) {
        self.interfaces.push(transition.description);
        all_interfaces.push(transition.description);
    }
}
