//! Block Types for pcap-ng files
use std::io::Read;

use crate::{
    byte_order::{ByteOrder, Endianness, ReadExt, UnexpectedSize},
    pcap_ng::PcapNgParseError,
};

mod enhanced_packet;
mod generic;
mod header;
mod interface;
mod name_resolution;
mod simple_packet;
pub use enhanced_packet::EnhancedPacket;
pub use generic::GenericBlock;
pub use header::{SHBOptionCodes, SectionHeaderBlock};
pub use interface::{InterfaceDescriptionBlock, InterfaceOptionCodes};
pub use name_resolution::NameResolutionBlock;
pub use simple_packet::SimplePacket;
pub trait Block {
    /// Returns the block ID for this block type
    fn block_id() -> u32
    where
        Self: Sized;
    /// Returns the block ID in little-endian format
    fn block_id_le() -> [u8; 4]
    where
        Self: Sized,
    {
        Self::block_id().to_le_bytes()
    }
    /// Returns the block ID in big-endian format
    fn block_id_be() -> [u8; 4]
    where
        Self: Sized,
    {
        Self::block_id().to_be_bytes()
    }
    /// Minimum size of the block, including the header
    ///
    /// Should be at least 12 bytes for the header and footer.
    fn minimum_size() -> usize {
        12 // Default minimum size for a block header
    }
    /// Reads the block from the reader with the given header and byte order
    ///
    /// If byte_order is None, it will be determined from the block header.
    ///
    /// For SectionHeaderBlock, the byte order is determined from the first 4 bytes of the blocks content.
    fn read_with_header<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Option<Endianness>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized;
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockHeader {
    pub block_id: [u8; 4],
    pub block_length: [u8; 4],
}
impl BlockHeader {
    pub fn new(block_id: [u8; 4], block_length: [u8; 4]) -> Self {
        Self {
            block_id,
            block_length,
        }
    }
    /// Returns the block ID as a u32
    pub fn block_id_as_u32(&self, endianness: impl ByteOrder) -> u32 {
        endianness.u32_from_bytes(self.block_id)
    }
    /// Returns the block length as a u32
    pub fn block_length_as_u32(&self, endianness: impl ByteOrder) -> u32 {
        endianness.u32_from_bytes(self.block_length)
    }
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, PcapNgParseError> {
        let block_id = reader.read_bytes::<4>()?;
        let block_length = reader.read_bytes::<4>()?;
        Ok(Self::new(block_id, block_length))
    }
    pub fn parse_from_bytes(bytes: &[u8]) -> Result<Self, PcapNgParseError> {
        if bytes.len() < 8 {
            return Err(PcapNgParseError::UnexpectedSize(UnexpectedSize {
                name: "BlockHeader",
                expected: 8,
                got: bytes.len(),
            }));
        }
        let block_id = [bytes[0], bytes[1], bytes[2], bytes[3]];
        let block_length = [bytes[4], bytes[5], bytes[6], bytes[7]];
        Ok(Self::new(block_id, block_length))
    }
    /// Checks if the block ID matches the expected block ID for the given block type
    pub(crate) fn matches_block_id<B: Block>(&self) -> Result<(), PcapNgParseError> {
        if self.block_id != B::block_id_le() && self.block_id != B::block_id_be() {
            return Err(PcapNgParseError::UnexpectedBlockId {
                expected_be: B::block_id().to_be_bytes(),
                expected_le: B::block_id().to_le_bytes(),
                got: self.block_id,
            });
        }
        Ok(())
    }
    /// Should not be used on SectionHeaderBlock
    #[allow(dead_code)]
    pub(crate) fn endianess_from_block<B: Block>(&self) -> Option<Endianness> {
        if self.block_id == B::block_id_le() {
            Some(Endianness::LittleEndian)
        } else if self.block_id == B::block_id_be() {
            Some(Endianness::BigEndian)
        } else {
            None
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapNgBlock {
    SectionHeader(SectionHeaderBlock),
    InterfaceDescription(InterfaceDescriptionBlock),
    SimplePacket(SimplePacket),
    EnhancedPacket(EnhancedPacket),
    NameResolution(NameResolutionBlock),
    Generic(GenericBlock),
}
impl PcapNgBlock {
    pub fn read<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Endianness,
    ) -> Result<Self, PcapNgParseError> {
        let block_id = header.block_id_as_u32(byte_order);
        match block_id {
            168627466 => Ok(PcapNgBlock::SectionHeader(
                SectionHeaderBlock::read_with_header(reader, header, Some(byte_order))?,
            )),
            1 => Ok(PcapNgBlock::InterfaceDescription(
                InterfaceDescriptionBlock::read_with_header(reader, header, Some(byte_order))?,
            )),
            3 => Ok(PcapNgBlock::SimplePacket(SimplePacket::read_with_header(
                reader,
                header,
                Some(byte_order),
            )?)),
            4 => Ok(PcapNgBlock::NameResolution(
                NameResolutionBlock::read_with_header(reader, header, Some(byte_order))?,
            )),
            6 => Ok(PcapNgBlock::EnhancedPacket(
                EnhancedPacket::read_with_header(reader, header, Some(byte_order))?,
            )),

            _ => Ok(PcapNgBlock::Generic(GenericBlock::read_with_header(
                reader, header, byte_order,
            )?)),
        }
    }
}
