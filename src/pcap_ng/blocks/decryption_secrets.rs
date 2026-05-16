//! Decryption Secrets Block (DSB)
use std::io::Read;

use crate::{
    byte_order::{Endianness, ReadExt, UndertminedByteOrder},
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
        options::BlockOptions,
        pad_length_to_32_bytes,
    },
};

/// Carries decryption secrets (e.g. TLS keylogs, WireGuard keys) for traffic
/// captured in the same file.
///
/// The `secrets_type` selects the format of `secrets_data` — well-known
/// values include `0x544c534b` (TLS Key Log) and `0x57475200` (WireGuard).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecryptionSecretsBlock {
    /// Total block length in bytes, including header and footer.
    pub block_length: u32,
    /// Selector for the format of `secrets_data` (e.g. TLS Key Log).
    pub secrets_type: u32,
    /// Length in bytes of `secrets_data`, excluding any padding.
    pub secrets_length: u32,
    /// Raw secrets bytes; interpretation depends on `secrets_type`.
    pub secrets_data: Vec<u8>,
    /// Optional block options associated with this DSB.
    pub options: Option<BlockOptions>,
}
impl<'b> Block<'b> for DecryptionSecretsBlock {
    fn block_id() -> u32 {
        0x0000_000A
    }
    fn block_id_le() -> [u8; 4] {
        [0x0A, 0x00, 0x00, 0x00]
    }
    fn block_id_be() -> [u8; 4] {
        [0x00, 0x00, 0x00, 0x0A]
    }
    fn minimum_size() -> usize {
        // 8 (BlockHeader) + 4 (secrets_type) + 4 (secrets_length) + 4 (trailing length)
        20
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
        let secrets_type = reader.read_u32(byte_order)?;
        let secrets_length = reader.read_u32(byte_order)?;
        let block_length = header.block_length_as_u32(byte_order);

        let padded_secrets_len = pad_length_to_32_bytes(secrets_length as usize);
        let mut secrets_data = vec![0u8; padded_secrets_len];
        reader.read_exact(&mut secrets_data)?;
        secrets_data.truncate(secrets_length as usize);

        let options_budget = (block_length as usize)
            .saturating_sub(Self::minimum_size())
            .saturating_sub(padded_secrets_len);
        let options = BlockOptions::read_bounded_option(reader, byte_order, options_budget)?;

        reader.read_bytes::<4>()?;
        Ok(Self {
            block_length,
            secrets_type,
            secrets_length,
            secrets_data,
            options,
        })
    }
}
#[cfg(feature = "tokio-async")]
mod tokio_async {
    use crate::pcap_ng::blocks::{DecryptionSecretsBlock, tokio_block::TokioAsyncBlock};

    impl<'b> TokioAsyncBlock<'b> for DecryptionSecretsBlock {}
}
