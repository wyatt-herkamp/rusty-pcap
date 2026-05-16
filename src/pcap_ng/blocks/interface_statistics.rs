//! Interface Statistics Block (ISB)
use std::io::Read;

use crate::{
    byte_order::{Endianness, ReadExt, UndertminedByteOrder},
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
        options::{BlockOptions, define_options_enum},
    },
};
define_options_enum! {
    /// Options for the Interface Statistics Block.
    enum ISBOptionCodes {
        IsbStartTime = 2,
        IsbEndTime = 3,
        IsbIfRecv = 4,
        IsbIfDrop = 5,
        IsbFilterAccept = 6,
        IsbOSDrop = 7,
        IsbUsrDeliv = 8,
    }
}

/// Reports per-interface capture statistics (received, dropped, etc.) for the
/// interface identified by `interface_id`. Typically emitted at the end of a
/// capture session, but may appear anywhere after the corresponding IDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceStatisticsBlock {
    /// Total block length in bytes, including header and footer.
    pub block_length: u32,
    /// Identifier of the interface these statistics apply to.
    pub interface_id: u32,
    /// Upper 32 bits of the statistics timestamp.
    pub timestamp_high: u32,
    /// Lower 32 bits of the statistics timestamp.
    pub timestamp_low: u32,
    /// Optional block options carrying the actual counter values.
    pub options: Option<BlockOptions>,
}
impl<'b> Block<'b> for InterfaceStatisticsBlock {
    fn block_id() -> u32 {
        5
    }
    fn block_id_le() -> [u8; 4] {
        [0x05, 0x00, 0x00, 0x00]
    }
    fn block_id_be() -> [u8; 4] {
        [0x00, 0x00, 0x00, 0x05]
    }
    fn minimum_size() -> usize {
        // 8 (BlockHeader) + 12 (interface_id + timestamp_high + timestamp_low) + 4 (trailing length)
        24
    }

    fn read_with_header<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Option<Endianness>,
        _: &'b mut Vec<u8>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized,
    {
        header.matches_block_id::<Self>()?;
        let byte_order = byte_order
            .or(header.endianness_from_block::<Self>())
            .ok_or(UndertminedByteOrder)?;
        let interface_id = reader.read_u32(byte_order)?;
        let timestamp_high = reader.read_u32(byte_order)?;
        let timestamp_low = reader.read_u32(byte_order)?;

        let block_length = header.block_length_as_u32(byte_order);
        let options_budget = (block_length as usize).saturating_sub(Self::minimum_size());
        let options = BlockOptions::read_bounded_option(reader, byte_order, options_budget)?;

        reader.read_bytes::<4>()?;
        Ok(Self {
            block_length,
            interface_id,
            timestamp_high,
            timestamp_low,
            options,
        })
    }
}
#[cfg(feature = "tokio-async")]
mod tokio_async {
    use crate::pcap_ng::blocks::{InterfaceStatisticsBlock, tokio_block::TokioAsyncBlock};

    impl<'b> TokioAsyncBlock<'b> for InterfaceStatisticsBlock {}
}
