#![forbid(unsafe_code)]
//! rusty-pcap is a pcap library for Rust
//!
//! 100% Rust implementation of a pcap reader
use crate::{
    byte_order::ByteOrder, pcap::file_header::MagicNumberAndEndianness, pcap_ng::PCAP_NG_MAGIC,
};

pub mod byte_order;
pub mod link_type;
pub mod pcap;
pub mod pcap_ng;

/// PcapFileType is the type of the pcap file, either Pcap or PcapNg
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapFileType {
    /// Pcap file format
    ///
    /// Based on the libpcap format
    Pcap,
    /// PcapNg file format
    PcapNg,
}
impl PcapFileType {
    /// Returns the PcapFileType from the magic number
    pub fn from_magic(magic: [u8; 4]) -> Option<Self> {
        if MagicNumberAndEndianness::try_from(magic).is_ok() {
            Some(PcapFileType::Pcap)
        } else if magic == PCAP_NG_MAGIC {
            Some(PcapFileType::PcapNg)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}
impl Version {
    /// Parses the version from the bytes
    #[inline(always)]
    pub(crate) fn parse(bytes: &[u8], byte_order: impl ByteOrder) -> Self {
        let major = byte_order.u16_from_bytes([bytes[0], bytes[1]]);
        let minor = byte_order.u16_from_bytes([bytes[2], bytes[3]]);
        Self { major, minor }
    }
}
