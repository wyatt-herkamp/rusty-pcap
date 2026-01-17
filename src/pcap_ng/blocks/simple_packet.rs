use std::io::Read;

use crate::{
    byte_order::{Endianness, ReadExt, UndertminedByteOrder},
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
        pad_length_to_32_bytes,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplePacket<'b> {
    pub block_length: u32,
    pub original_length: u32,
    pub content: &'b [u8],
}
impl<'b> Block<'b> for SimplePacket<'b> {
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
        buffer: &'b mut Vec<u8>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized,
    {
        header.matches_block_id::<Self>()?;
        let byte_order = byte_order
            .or(header.endianness_from_block::<Self>())
            .ok_or(UndertminedByteOrder)?;
        Self::read_with_header_no_block_check(reader, header, byte_order, buffer)
    }
    fn read_with_header_no_block_check<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Endianness,
        buffer: &'b mut Vec<u8>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized + 'b,
    {
        let original_length = reader.read_u32(byte_order)?;
        let block_length = header.block_length_as_u32(byte_order);
        // This might be wrong...
        let padded_length = pad_length_to_32_bytes(original_length as usize);
        // Ensure buffer is large enough
        if buffer.len() < padded_length {
            buffer.resize(padded_length, 0);
        }
        reader.read_exact(&mut buffer[..padded_length])?;

        // Read the footer (4 bytes)
        reader.read_bytes::<4>()?;
        Ok(Self {
            block_length,
            original_length,
            content: &buffer[..block_length as usize],
        })
    }
}
#[cfg(feature = "tokio-async")]
mod tokio_async {
    use crate::pcap_ng::blocks::{SimplePacket, tokio_block::TokioAsyncBlock};

    impl<'b> TokioAsyncBlock<'b> for SimplePacket<'b> {}
}
