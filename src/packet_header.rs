use std::io::Read;

use crate::{Endianness, PcapParseError};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub incl_len: u32,
    pub orig_len: u32,
}
impl PacketHeader {
    pub fn new(ts_sec: u32, ts_usec: u32, incl_len: u32, orig_len: u32) -> Self {
        Self {
            ts_sec,
            ts_usec,
            incl_len,
            orig_len,
        }
    }
    pub fn read<R: Read>(reader: &mut R, endianness: Endianness) -> Result<Self, PcapParseError> {
        match endianness {
            Endianness::BigEndian => Self::read_big_endian(reader),
            Endianness::LittleEndian => Self::read_little_endian(reader),
        }
    }
    pub fn parse_bytes(bytes: &[u8; 16], endianness: Endianness) -> Result<Self, PcapParseError> {
        match endianness {
            Endianness::BigEndian => Self::parse_be_bytes(bytes),
            Endianness::LittleEndian => Self::parse_le_bytes(bytes),
        }
    }
    pub fn read_big_endian<R: Read>(reader: &mut R) -> Result<Self, PcapParseError> {
        let mut header = [0u8; 16];
        reader.read_exact(&mut header)?;
        Self::parse_be_bytes(&header)
    }
    pub fn parse_be_bytes(bytes: &[u8; 16]) -> Result<Self, PcapParseError> {
        let ts_sec = u32::from_be_bytes(bytes[0..4].try_into().unwrap());
        let ts_usec = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let incl_len = u32::from_be_bytes(bytes[8..12].try_into().unwrap());
        let orig_len = u32::from_be_bytes(bytes[12..16].try_into().unwrap());
        Ok(Self {
            ts_sec,
            ts_usec,
            incl_len,
            orig_len,
        })
    }

    pub fn read_little_endian<R: Read>(reader: &mut R) -> Result<Self, PcapParseError> {
        let mut header = [0u8; 16];
        reader.read_exact(&mut header)?;
        Self::parse_le_bytes(&header)
    }
    pub fn parse_le_bytes(bytes: &[u8; 16]) -> Result<Self, PcapParseError> {
        let ts_sec = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        let ts_usec = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        let incl_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        let orig_len = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        Ok(Self {
            ts_sec,
            ts_usec,
            incl_len,
            orig_len,
        })
    }
}
