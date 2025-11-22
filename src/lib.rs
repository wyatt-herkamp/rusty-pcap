use thiserror::Error;

pub mod byte_order;
pub mod file_header;
pub mod link_type;
pub mod packet_header;
pub mod sync;
#[cfg(feature = "tokio-async")]
pub mod tokio_impl;
#[derive(Debug, Error)]
pub enum PcapParseError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error("Invalid magic number got {0:?}")]
    InvalidMagicNumber(Option<[u8; 4]>),
    #[error("Invalid link type: {0}")]
    InvalidLinkType(u16),
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
    UnexpectedSize(#[from] byte_order::UnexpectedSize),
}
