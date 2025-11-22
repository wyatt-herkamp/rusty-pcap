use std::io::Read;

use crate::{
    PcapParseError,
    byte_order::{Endianness, ExtendedByteOrder},
};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    /// The length of the packet data included in the file
    pub include_len: u32,
    /// The original length of the packet data
    pub orig_len: u32,
}
impl PacketHeader {
    pub fn new(ts_sec: u32, ts_usec: u32, incl_len: u32, orig_len: u32) -> Self {
        Self {
            ts_sec,
            ts_usec,
            include_len: incl_len,
            orig_len,
        }
    }
    /// Reads the packet header from the reader
    /// Returns `Ok(Self)` on success, or `Err` if there was an error
    /// reading the packet header
    /// The endianness is used to determine how to read the bytes
    #[inline(always)]
    pub fn read<R: Read>(reader: &mut R, endianness: Endianness) -> Result<Self, PcapParseError> {
        let mut header = [0u8; 16];
        reader.read_exact(&mut header)?;
        Self::parse_bytes(&header, endianness)
    }
    #[inline(always)]
    pub fn parse_bytes(bytes: &[u8; 16], endianness: Endianness) -> Result<Self, PcapParseError> {
        let ts = endianness.try_u32_from_bytes(&bytes[0..4])?;
        let ts_usec = endianness.try_u32_from_bytes(&bytes[4..8])?;
        let incl_len = endianness.try_u32_from_bytes(&bytes[8..12])?;
        let orig_len = endianness.try_u32_from_bytes(&bytes[12..16])?;
        Ok(Self {
            ts_sec: ts,
            ts_usec,
            include_len: incl_len,
            orig_len,
        })
    }
}
