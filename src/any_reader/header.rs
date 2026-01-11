use crate::{pcap::packet_header::PacketHeader, pcap_ng::options::BlockOptions};

/// A unified packet header enum that can represent both pcap and pcapng packet headers
///
/// This enum encapsulates the different packet header formats found in pcap and pcapng files,
/// allowing for a consistent interface when working with packet headers regardless of the file type.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyPacketHeader {
    Pcap(PacketHeader),
    PcapNgSimple {
        block_length: u32,
        original_length: u32,
    },
    PcapNgEnhanced {
        block_length: u32,
        interface_id: u32,
        timestamp_high: u32,
        timestamp_low: u32,
        captured_length: u32,
        original_length: u32,
        options: Option<BlockOptions>,
    },
}
impl AnyPacketHeader {
    pub fn original_length(&self) -> u32 {
        match self {
            AnyPacketHeader::Pcap(header) => header.orig_len,
            AnyPacketHeader::PcapNgSimple {
                original_length, ..
            } => *original_length,
            AnyPacketHeader::PcapNgEnhanced {
                original_length, ..
            } => *original_length,
        }
    }
}

impl From<PacketHeader> for AnyPacketHeader {
    fn from(value: PacketHeader) -> Self {
        AnyPacketHeader::Pcap(value)
    }
}
