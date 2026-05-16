//! Simple Packet Block (SPB)
use std::io::Read;

use crate::{
    byte_order::{Endianness, ReadExt, UndertminedByteOrder},
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
    },
};

/// A pcap-ng Simple Packet Block (SPB).
///
/// A minimal packet record carrying only the original wire length and the
/// captured bytes; intended for capture pipelines that don't need
/// per-interface metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimplePacket<'b> {
    /// Total block length in bytes, including header and footer.
    pub block_length: u32,
    /// Length of the packet on the wire.
    pub original_length: u32,
    /// Captured packet bytes, borrowed from the reader's packet buffer.
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
        // The SPB carries `min(snap_length, original_length)` bytes of packet
        // data, padded to 32 bits. The captured (possibly truncated) payload
        // size is recoverable from the block-length alone: subtract 8 bytes
        // of BlockHeader, 4 bytes of `original_length`, and 4 bytes of the
        // trailing block_length footer.
        let captured_padded = (block_length as usize).saturating_sub(16);
        if buffer.len() < captured_padded {
            buffer.resize(captured_padded, 0);
        }
        reader.read_exact(&mut buffer[..captured_padded])?;

        // If the on-wire packet fits in the captured region, expose the
        // unpadded slice; otherwise the packet was snap-length-truncated and
        // we keep the captured-padded slice (the last 0-3 bytes may be zero
        // padding that cannot be distinguished from real packet data without
        // the IDB's snap_length).
        let content_len = captured_padded.min(original_length as usize);

        // Read the footer (4 bytes)
        reader.read_bytes::<4>()?;
        Ok(Self {
            block_length,
            original_length,
            content: &buffer[..content_len],
        })
    }
}
#[cfg(feature = "tokio-async")]
mod tokio_async {
    use crate::pcap_ng::blocks::{SimplePacket, tokio_block::TokioAsyncBlock};

    impl<'b> TokioAsyncBlock<'b> for SimplePacket<'b> {}
}
