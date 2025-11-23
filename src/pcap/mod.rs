pub mod file_header;
pub mod packet_header;
pub mod sync;
#[cfg(feature = "tokio-async")]
pub mod tokio_impl;
use thiserror::Error;

use crate::{byte_order::UnexpectedSize, link_type::InvalidLinkType};

#[derive(Debug, Error)]
pub enum PcapParseError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("Invalid magic number got {0:?}")]
    InvalidMagicNumber(Option<[u8; 4]>),
    #[error(transparent)]
    InvalidLinkType(#[from] InvalidLinkType),
    #[error(
        "Invalid packet length: snap length {snap_length} is greater than included length {incl_len}"
    )]
    InvalidPacketLength { snap_length: u32, incl_len: u32 },
    #[error("Invalid version")]
    InvalidVersion,
    /// This should never happen. But preventing panics
    #[error(transparent)]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    UnexpectedSize(#[from] UnexpectedSize),
}
