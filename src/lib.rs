//! rusty-pcap is a pcap library for Rust
//!
//! 100% Rust implementation of a pcap reader
use crate::{pcap::file_header::MagicNumberAndEndianness, pcap_ng::PCAP_NG_MAGIC};

pub mod byte_order;
pub mod link_type;
pub mod pcap;
pub mod pcap_ng;

pub mod version;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapFileType {
    Pcap,
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
