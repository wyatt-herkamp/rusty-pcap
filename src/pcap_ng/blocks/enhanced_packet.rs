use std::{
    io::{Cursor, Read},
    vec,
};

use crate::{
    byte_order::{Endianness, ReadExt, UndertminedByteOrder},
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
        options::BlockOptions,
        pad_length_to_32_bytes,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnhancedPacket {
    pub block_length: u32,
    // 8..12
    pub interface_id: u32,
    // 12..16
    pub timestamp_high: u32,
    // 16..20
    pub timestamp_low: u32,
    // 20..24
    pub captured_length: u32,
    // 24..28
    pub original_length: u32,

    pub content: Vec<u8>,

    pub options: Option<BlockOptions>,
}
impl Block for EnhancedPacket {
    fn block_id() -> u32 {
        6
    }

    fn minimum_size() -> usize {
        32
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
            .or(header.endianess_from_block::<Self>())
            .ok_or(UndertminedByteOrder)?;
        let mut cursor = Cursor::new(reader.read_bytes::<20>()?);

        let interface_id = cursor.read_u32(byte_order)?;
        let timestamp_high = cursor.read_u32(byte_order)?;
        let timestamp_low = cursor.read_u32(byte_order)?;
        let captured_length = cursor.read_u32(byte_order)?;
        let original_length = cursor.read_u32(byte_order)?;

        let block_length = header.block_length_as_u32(byte_order);
        let padded_length = pad_length_to_32_bytes(captured_length as usize);
        let mut content = vec![0; padded_length];
        reader.read_exact(&mut content)?;

        let options_space = block_length as usize - Self::minimum_size() - padded_length;
        let options = if options_space > 0 {
            BlockOptions::read_option(reader, byte_order)?
        } else {
            None
        };
        // Read the footer (4 bytes)
        reader.read_bytes::<4>()?;
        Ok(Self {
            block_length,
            interface_id,
            timestamp_high,
            timestamp_low,
            captured_length,
            original_length,
            content,
            options,
        })
    }
}
impl EnhancedPacket {
    pub fn read<R: Read>(reader: &mut R, byte_order: Endianness) -> Result<Self, PcapNgParseError> {
        let header = BlockHeader::read(reader)?;
        Self::read_with_header::<_>(reader, &header, Some(byte_order))
    }
}
