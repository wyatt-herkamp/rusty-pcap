//! Block Types for pcap-ng files
use std::io::{Read, Write};

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
pub trait Block<'b> {
    /// Returns the block ID for this block type
    fn block_id() -> u32
    where
        Self: Sized;
    /// Returns the block ID in little-endian format
    #[inline(always)]
    fn block_id_le() -> [u8; 4]
    where
        Self: Sized,
    {
        Self::block_id().to_le_bytes()
    }
    /// Returns the block ID in big-endian format
    #[inline(always)]
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
        packet_buffer: &'b mut Vec<u8>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized + 'b;

    fn read_with_header_no_block_check<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Endianness,
        packet_buffer: &'b mut Vec<u8>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized + 'b,
    {
        Self::read_with_header(reader, header, Some(byte_order), packet_buffer)
    }
}
#[cfg(feature = "tokio-async")]
mod tokio_block {
    #![allow(dead_code)]
    use tokio::io::{AsyncRead, AsyncReadExt};

    use crate::{
        byte_order::{Endianness, UndertminedByteOrder},
        pcap_ng::{
            PcapNgParseError,
            blocks::{
                Block, BlockHeader, EnhancedPacket, GenericBlock, InterfaceDescriptionBlock,
                NameResolutionBlock, PcapNgBlock, SectionHeaderBlock, SimplePacket,
            },
        },
    };

    pub trait TokioAsyncBlock<'b>: Block<'b> {
        /// Asynchronously reads the block from the reader with the given header and byte order
        ///
        /// # Default Implementation
        ///
        /// By default, this implementation reads the entire block content into memory
        /// and then calls the synchronous [Block::read_with_header] method.
        fn async_read_with_header<R: AsyncRead + Unpin>(
            reader: &mut R,
            header: &BlockHeader,
            byte_order: Option<Endianness>,
            buffer: &'b mut Vec<u8>,
        ) -> impl Future<Output = Result<Self, PcapNgParseError>>
        where
            Self: Sized + 'b,
        {
            async move {
                header.matches_block_id::<Self>()?;
                let determined_byte_order = byte_order
                    .or(header.endianness_from_block::<Self>())
                    .ok_or(UndertminedByteOrder)?;
                let block_length = header.block_length_as_u32(determined_byte_order) as usize - 8;
                let mut content = vec![0u8; block_length];
                reader.read_exact(&mut content).await?;
                let mut cursor = std::io::Cursor::new(content);
                Self::read_with_header(&mut cursor, header, byte_order, buffer)
            }
        }
    }
    impl<'b> PcapNgBlock<'b> {
        pub async fn read_async<R: AsyncRead + Unpin>(
            reader: &mut R,
            header: &BlockHeader,
            byte_order: Endianness,
            packet_buffer: &'b mut Vec<u8>,
        ) -> Result<Self, PcapNgParseError> {
            let block_id = header.block_id_as_u32(byte_order);
            match block_id {
                168627466 => Ok(PcapNgBlock::SectionHeader(
                    SectionHeaderBlock::async_read_with_header(
                        reader,
                        header,
                        Some(byte_order),
                        packet_buffer,
                    )
                    .await?,
                )),
                1 => Ok(PcapNgBlock::InterfaceDescription(
                    InterfaceDescriptionBlock::async_read_with_header(
                        reader,
                        header,
                        Some(byte_order),
                        packet_buffer,
                    )
                    .await?,
                )),
                3 => Ok(PcapNgBlock::SimplePacket(
                    SimplePacket::async_read_with_header(
                        reader,
                        header,
                        Some(byte_order),
                        packet_buffer,
                    )
                    .await?,
                )),
                4 => Ok(PcapNgBlock::NameResolution(
                    NameResolutionBlock::async_read_with_header(
                        reader,
                        header,
                        Some(byte_order),
                        packet_buffer,
                    )
                    .await?,
                )),
                6 => Ok(PcapNgBlock::EnhancedPacket(
                    EnhancedPacket::async_read_with_header(
                        reader,
                        header,
                        Some(byte_order),
                        packet_buffer,
                    )
                    .await?,
                )),
                _ => Ok(PcapNgBlock::Generic(
                    GenericBlock::read_async_with_header(reader, header, byte_order).await?,
                )),
            }
        }
    }
}
#[cfg(feature = "tokio-async")]
pub use tokio_block::TokioAsyncBlock;
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
    pub(crate) fn matches_block_id<'b, B: Block<'b>>(&self) -> Result<(), PcapNgParseError> {
        if self.block_id != B::block_id_le() && self.block_id != B::block_id_be() {
            return Err(PcapNgParseError::UnexpectedBlockId {
                expected_be: B::block_id().to_be_bytes(),
                expected_le: B::block_id().to_le_bytes(),
                got: self.block_id,
            });
        }
        Ok(())
    }
    /// Will panic if the block ID does not match the expected block ID for the given block type
    pub(crate) fn endianness_from_block<'b, B: Block<'b>>(&self) -> Option<Endianness> {
        debug_assert_ne!(
            B::block_id_be(),
            B::block_id_le(),
            "Unable to determine endianness for {}",
            std::any::type_name::<B>()
        );
        if self.block_id == B::block_id_le() {
            Some(Endianness::LittleEndian)
        } else if self.block_id == B::block_id_be() {
            Some(Endianness::BigEndian)
        } else {
            None
        }
    }
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        writer.write_all(&self.block_id)?;
        writer.write_all(&self.block_length)?;
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PcapNgBlock<'b> {
    SectionHeader(SectionHeaderBlock),
    InterfaceDescription(InterfaceDescriptionBlock),
    SimplePacket(SimplePacket<'b>),
    EnhancedPacket(EnhancedPacket<'b>),
    NameResolution(NameResolutionBlock),
    Generic(GenericBlock),
}
impl<'b> PcapNgBlock<'b> {
    pub fn read<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Endianness,
        packet_buffer: &'b mut Vec<u8>,
    ) -> Result<Self, PcapNgParseError> {
        let block_id = header.block_id_as_u32(byte_order);
        match block_id {
            6 => Ok(PcapNgBlock::EnhancedPacket(
                EnhancedPacket::read_with_header_no_block_check(
                    reader,
                    header,
                    byte_order,
                    packet_buffer,
                )?,
            )),
            3 => Ok(PcapNgBlock::SimplePacket(
                SimplePacket::read_with_header_no_block_check(
                    reader,
                    header,
                    byte_order,
                    packet_buffer,
                )?,
            )),
            168627466 => Ok(PcapNgBlock::SectionHeader(
                SectionHeaderBlock::read_with_header(
                    reader,
                    header,
                    Some(byte_order),
                    packet_buffer,
                )?,
            )),
            1 => Ok(PcapNgBlock::InterfaceDescription(
                InterfaceDescriptionBlock::read_with_header(
                    reader,
                    header,
                    Some(byte_order),
                    packet_buffer,
                )?,
            )),

            4 => Ok(PcapNgBlock::NameResolution(
                NameResolutionBlock::read_with_header(
                    reader,
                    header,
                    Some(byte_order),
                    packet_buffer,
                )?,
            )),

            _ => Ok(PcapNgBlock::Generic(GenericBlock::read_with_header(
                reader, header, byte_order,
            )?)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic]
    fn endianness_from_block_panics() {
        let block = BlockHeader {
            block_id: SectionHeaderBlock::block_id_le(),
            block_length: [0; 4],
        };
        block.endianness_from_block::<SectionHeaderBlock>();
    }

    #[test]
    fn endianness_from_block() {
        let block = BlockHeader {
            block_id: InterfaceDescriptionBlock::block_id_le(),
            block_length: [0; 4],
        };
        assert_eq!(
            block.endianness_from_block::<InterfaceDescriptionBlock>(),
            Some(Endianness::LittleEndian)
        );
        let block = BlockHeader {
            block_id: InterfaceDescriptionBlock::block_id_be(),
            block_length: [0; 4],
        };
        assert_eq!(
            block.endianness_from_block::<InterfaceDescriptionBlock>(),
            Some(Endianness::BigEndian)
        );
    }
}
