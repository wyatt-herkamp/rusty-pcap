use std::{io::Read, vec};

use crate::{
    byte_order::{Endianness, ReadExt, UndertminedByteOrder},
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
        pad_length_to_32_bytes,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplePacket {
    pub block_length: u32,
    pub original_length: u32,
    pub content: Vec<u8>,
}
impl Block for SimplePacket {
    fn block_id() -> u32 {
        3
    }

    fn minimum_size() -> usize {
        16
    }
    fn read_with_header<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Option<crate::byte_order::Endianness>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized,
    {
        header.matches_block_id::<Self>()?;
        let byte_order = byte_order
            .or(header.endianness_from_block::<Self>())
            .ok_or(UndertminedByteOrder)?;
        let original_length = reader.read_u32(byte_order)?;
        let block_length = header.block_length_as_u32(byte_order);
        // This might be wrong...
        let padded_length = pad_length_to_32_bytes(original_length as usize);
        let mut content = vec![0; padded_length];
        reader.read_exact(&mut content)?;

        // Read the footer (4 bytes)
        reader.read_bytes::<4>()?;
        Ok(Self {
            block_length,
            original_length,
            content,
        })
    }
}
impl SimplePacket {
    pub fn read<R: Read>(reader: &mut R, byte_order: Endianness) -> Result<Self, PcapNgParseError> {
        let header = BlockHeader::read(reader)?;
        Self::read_with_header::<_>(reader, &header, Some(byte_order))
    }
}
