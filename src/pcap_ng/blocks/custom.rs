//! Custom Block (CB) and Custom Block, Do-Not-Copy (DCB)
//!
//! Per the pcapng spec the same block layout is reused for two block IDs:
//! `0x00000BAD` (may be copied to a new file when manipulated) and
//! `0x40000BAD` (must not be copied). They are distinguished only by the
//! block-ID — the body layout is identical.
//!
//! The pcapng spec is ambiguous about where the variable-length Custom Data
//! ends and Options begin (no length field separates them, and options aren't
//! self-delimiting from arbitrary preceding bytes). Because of that this
//! parser does not attempt to split the body: everything between the PEN and
//! the trailing block-length is preserved verbatim as `custom_data`.
//! Consumers that know the PEN-specific layout can interpret it themselves.
use std::io::Read;

use crate::{
    byte_order::{Endianness, ReadExt, UndertminedByteOrder},
    pcap_ng::{PcapNgParseError, blocks::BlockHeader},
};

/// pcapng block-ID for a Custom Block that may be copied.
pub const CUSTOM_BLOCK_COPYABLE: u32 = 0x0000_0BAD;
/// pcapng block-ID for a Custom Block that must not be copied.
pub const CUSTOM_BLOCK_DO_NOT_COPY: u32 = 0x4000_0BAD;

/// Returns true if `block_id` is one of the two Custom Block IDs.
pub const fn is_custom_block_id(block_id: u32) -> bool {
    block_id == CUSTOM_BLOCK_COPYABLE || block_id == CUSTOM_BLOCK_DO_NOT_COPY
}

/// Carries vendor-specific data identified by a Private Enterprise Number.
///
/// The `block_id` field distinguishes the may-copy ([`CUSTOM_BLOCK_COPYABLE`])
/// and do-not-copy ([`CUSTOM_BLOCK_DO_NOT_COPY`]) flavors — call
/// [`Self::copy_allowed`] for a friendlier check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomBlock {
    /// Total block length in bytes, including header and footer.
    pub block_length: u32,
    /// Raw block-ID — `CUSTOM_BLOCK_COPYABLE` or `CUSTOM_BLOCK_DO_NOT_COPY`.
    pub block_id: u32,
    /// IANA Private Enterprise Number identifying the vendor of this block.
    pub pen: u32,
    /// Opaque body bytes between the PEN and the trailing block-length.
    ///
    /// Per the pcapng spec the body may optionally contain a trailing
    /// block-options list, but the spec provides no reliable way for a
    /// generic parser to locate the boundary between Custom Data and
    /// Options. Implementations that know the PEN-specific layout can
    /// post-process these bytes themselves.
    pub custom_data: Vec<u8>,
}
impl CustomBlock {
    /// Returns `true` if this block is the may-copy variant
    /// ([`CUSTOM_BLOCK_COPYABLE`]).
    pub fn copy_allowed(&self) -> bool {
        self.block_id == CUSTOM_BLOCK_COPYABLE
    }

    /// Reads a Custom Block whose 8-byte header has already been parsed.
    pub fn read_with_header<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Option<Endianness>,
    ) -> Result<Self, PcapNgParseError> {
        let byte_order = byte_order
            .or(determine_byte_order(header))
            .ok_or(UndertminedByteOrder)?;
        Self::read_with_header_no_block_check(reader, header, byte_order)
    }

    /// Like [`read_with_header`](Self::read_with_header) but assumes the
    /// caller has already validated the block-ID and resolved the byte
    /// order.
    pub fn read_with_header_no_block_check<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Endianness,
    ) -> Result<Self, PcapNgParseError> {
        let block_length = header.block_length_as_u32(byte_order);
        let block_id = header.block_id_as_u32(byte_order);
        let pen = reader.read_u32(byte_order)?;
        // 8 (BlockHeader) + 4 (PEN) + 4 (trailing length) = 16 fixed bytes
        let body_len = (block_length as usize).saturating_sub(16);
        let mut custom_data = vec![0u8; body_len];
        reader.read_exact(&mut custom_data)?;
        reader.read_bytes::<4>()?;
        Ok(Self {
            block_length,
            block_id,
            pen,
            custom_data,
        })
    }
}

/// Resolves the section byte-order from a Custom Block's 4-byte block-ID.
///
/// Both Custom Block IDs are byte-order-distinguishable (the spec values
/// `0x00000BAD` and `0x40000BAD` differ in their top byte).
fn determine_byte_order(header: &BlockHeader) -> Option<Endianness> {
    let raw = header.block_id;
    if raw == CUSTOM_BLOCK_COPYABLE.to_le_bytes() || raw == CUSTOM_BLOCK_DO_NOT_COPY.to_le_bytes() {
        Some(Endianness::LittleEndian)
    } else if raw == CUSTOM_BLOCK_COPYABLE.to_be_bytes()
        || raw == CUSTOM_BLOCK_DO_NOT_COPY.to_be_bytes()
    {
        Some(Endianness::BigEndian)
    } else {
        None
    }
}

#[cfg(feature = "tokio-async")]
mod tokio_async {
    use tokio::io::{AsyncRead, AsyncReadExt as _};

    use crate::{
        byte_order::{Endianness, tokio_async::AsyncReadExt as _},
        pcap_ng::{
            PcapNgParseError,
            blocks::{BlockHeader, custom::CustomBlock},
        },
    };

    impl CustomBlock {
        /// Async counterpart to [`CustomBlock::read_with_header_no_block_check`].
        pub async fn async_read_with_header_no_block_check<R: AsyncRead + Unpin>(
            reader: &mut R,
            header: &BlockHeader,
            byte_order: Endianness,
        ) -> Result<Self, PcapNgParseError> {
            let block_length = header.block_length_as_u32(byte_order);
            let block_id = header.block_id_as_u32(byte_order);
            let pen =
                <R as crate::byte_order::tokio_async::AsyncReadExt>::read_u32(reader, byte_order)
                    .await?;
            let body_len = (block_length as usize).saturating_sub(16);
            let mut custom_data = vec![0u8; body_len];
            reader.read_exact(&mut custom_data).await?;
            reader.read_bytes::<4>().await?;
            Ok(Self {
                block_length,
                block_id,
                pen,
                custom_data,
            })
        }
    }
}
