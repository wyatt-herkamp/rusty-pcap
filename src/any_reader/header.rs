use crate::{pcap::packet_header::PacketHeader, pcap_ng::options::BlockOptions};

/// A unified packet header enum that can represent both pcap and pcapng packet headers
///
/// This enum encapsulates the different packet header formats found in pcap and pcapng files,
/// allowing for a consistent interface when working with packet headers regardless of the file type.
///
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnyPacketHeader {
    /// A header from a classic pcap file.
    Pcap(PacketHeader),
    /// A header from a pcap-ng Simple Packet Block.
    PcapNgSimple {
        /// Total block length in bytes, including header and footer.
        block_length: u32,
        /// Length of the packet on the wire.
        original_length: u32,
    },
    /// A header from a pcap-ng Enhanced Packet Block.
    PcapNgEnhanced {
        /// Total block length in bytes, including header and footer.
        block_length: u32,
        /// Identifier of the interface this packet was captured on.
        interface_id: u32,
        /// Upper 32 bits of the packet timestamp.
        timestamp_high: u32,
        /// Lower 32 bits of the packet timestamp.
        timestamp_low: u32,
        /// Number of bytes captured (may be less than `original_length`).
        captured_length: u32,
        /// Length of the packet on the wire.
        original_length: u32,
        /// Optional block options associated with this packet.
        options: Option<BlockOptions>,
    },
}
impl AnyPacketHeader {
    /// Returns the on-the-wire length of the packet, regardless of which
    /// underlying header variant is in use.
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
