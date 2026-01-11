//! This module provides pcap-ng parsing functionality
//!
//! [Source](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html)
//!
//! Currently, only supports reading files from beginning to end and does not support reverse reading.
use thiserror::Error;

use crate::{byte_order::Endianness, link_type::InvalidLinkType};
pub mod blocks;
pub mod options;
pub mod sync;
#[cfg(feature = "tokio-async")]
pub mod tokio_impl;
/// Magic number for pcap-ng files
///
/// All pcap-ng files should start with this magic number
pub const PCAP_NG_MAGIC: [u8; 4] = [0x0A, 0x0D, 0x0D, 0x0A];
#[derive(Debug, Error)]
pub enum PcapNgParseError {
    #[error("Invalid block ID: expected {expected_be:?} or {expected_le:?}, got {got:?}")]
    UnexpectedBlockId {
        expected_be: [u8; 4],
        expected_le: [u8; 4],
        got: [u8; 4],
    },
    #[error("Invalid endianness: got {got:?}")]
    InvalidEndianness { got: [u8; 4] },
    /// This should never happen. But preventing panics
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("Minimum size for this block is {0} bytes, but got {1} bytes")]
    MinimumSizeNotMet(usize, usize),
    #[error(transparent)]
    UnexpectedSize(#[from] crate::byte_order::UnexpectedSize),
    #[error("Error parsing options: {0}")]
    OptionParseError(#[from] options::OptionParseError),
    #[error(transparent)]
    InvalidLinkType(#[from] InvalidLinkType),
    #[error(transparent)]
    UndeterminedByteOrder(#[from] crate::byte_order::UndertminedByteOrder),
}

impl Endianness {
    pub fn from_pcap_ng_bytes(bytes: &[u8; 4]) -> Result<Self, PcapNgParseError> {
        match bytes {
            [0x1A, 0x2B, 0x3C, 0x4D] => Ok(Self::BigEndian),
            [0x4D, 0x3C, 0x2B, 0x1A] => Ok(Self::LittleEndian),
            _ => Err(PcapNgParseError::InvalidEndianness { got: *bytes }),
        }
    }
}

/// Pads the length to the next multiple of 32 bytes
pub(crate) fn pad_length_to_32_bytes(length: usize) -> usize {
    if length.is_multiple_of(4) {
        length
    } else {
        length + (4 - (length % 4))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_pad_length_to_32_bytes() {
        assert_eq!(pad_length_to_32_bytes(0), 0);
        assert_eq!(pad_length_to_32_bytes(1), 4);
        assert_eq!(pad_length_to_32_bytes(3), 4);
        assert_eq!(pad_length_to_32_bytes(4), 4);
        assert_eq!(pad_length_to_32_bytes(5), 8);
        assert_eq!(pad_length_to_32_bytes(7), 8);
        assert_eq!(pad_length_to_32_bytes(8), 8);
        assert_eq!(pad_length_to_32_bytes(9), 12);
    }
}
