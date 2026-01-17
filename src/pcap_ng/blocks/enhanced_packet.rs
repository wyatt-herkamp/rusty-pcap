use std::io::{Cursor, Read, Write};

use crate::{
    byte_order::{ByteOrder, Endianness, ReadExt, UndertminedByteOrder, WriteExt},
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
        options::BlockOptions,
        pad_length_to_32_bytes,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnhancedPacket<'b> {
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

    pub content: &'b [u8],

    pub options: Option<BlockOptions>,
}
impl<'b> EnhancedPacket<'b> {
    /// Writes the enhanced packet block to the given writer using the specified byte order.
    ///
    /// Currently, this is unstable and may change in the future.
    pub fn write<W: Write, B: ByteOrder>(
        &self,
        writer: &mut W,
        byte_order: B,
    ) -> Result<(), std::io::Error> {
        let mut buffer = Cursor::new(Vec::with_capacity(Self::minimum_size()));

        buffer.write_u32(self.interface_id, byte_order)?;
        buffer.write_u32(self.timestamp_high, byte_order)?;
        buffer.write_u32(self.timestamp_low, byte_order)?;
        buffer.write_u32(self.captured_length, byte_order)?;
        buffer.write_u32(self.original_length, byte_order)?;
        buffer.write_all(self.content)?;
        let padding = pad_length_to_32_bytes(self.content.len()) - self.content.len();
        if padding > 0 {
            buffer.write_all(&vec![0u8; padding])?;
        }
        if let Some(options) = &self.options {
            options.write(&mut buffer, byte_order)?;
        }
        let packet_length = (buffer.get_ref().len() as u32) + 12;
        let block_header = BlockHeader::new(
            byte_order.u32_to_bytes(Self::block_id()),
            byte_order.u32_to_bytes(packet_length),
        );

        block_header.write(writer)?;
        writer.write_all(buffer.get_ref())?;
        writer.write_u32(Self::block_id(), byte_order)?;

        Ok(())
    }
}
impl<'b> Block<'b> for EnhancedPacket<'b> {
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
        buffer: &'b mut Vec<u8>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized + 'b,
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
        let bytes = reader.read_bytes::<20>()?;
        let interface_id = byte_order.u32_from_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let timestamp_high = byte_order.u32_from_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let timestamp_low = byte_order.u32_from_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        let captured_length =
            byte_order.u32_from_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let original_length =
            byte_order.u32_from_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);

        let block_length = header.block_length_as_u32(byte_order);
        let padded_length = pad_length_to_32_bytes(captured_length as usize);
        // Ensure buffer is large enough
        if buffer.len() < padded_length {
            buffer.resize(padded_length, 0);
        }
        reader.read_exact(&mut buffer[..padded_length])?;

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
            content: &buffer[..captured_length as usize],
            options,
        })
    }
}

#[cfg(feature = "tokio-async")]
mod tokio_async {
    use crate::pcap_ng::blocks::{EnhancedPacket, tokio_block::TokioAsyncBlock};

    impl<'b> TokioAsyncBlock<'b> for EnhancedPacket<'b> {}
}

#[cfg(test)]
mod tests {
    use crate::byte_order::{Endianness, LittleEndian};

    use super::*;

    #[test]
    fn test_enhanced_packet_write() {
        let content = vec![1; 2048];
        let options = None;
        let packet = EnhancedPacket {
            block_length: 32,
            interface_id: 1,
            timestamp_high: 0,
            timestamp_low: 0,
            captured_length: content.len() as u32,
            original_length: content.len() as u32,
            content: &content,
            options,
        };
        let mut buffer = Vec::new();
        packet.write(&mut buffer, LittleEndian).unwrap();

        assert!(!buffer.is_empty());
        let mut reader = std::io::Cursor::new(&buffer);

        let header = BlockHeader::read(&mut reader).unwrap();

        let mut content_buffer = Vec::new();
        let packet = EnhancedPacket::read_with_header(
            &mut reader,
            &header,
            Some(Endianness::LittleEndian),
            &mut content_buffer,
        )
        .unwrap();
        assert_eq!(packet.content, &content[..]);
        assert_eq!(packet.captured_length, content.len() as u32);
        assert_eq!(packet.original_length, content.len() as u32);
        assert!(packet.options.is_none());
    }
}
