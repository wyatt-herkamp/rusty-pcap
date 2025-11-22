//! This is a module for handling byte order in pcap files

use thiserror::Error;

/// Represents a trait for byte order operations
pub(crate) trait ByteOrder: Clone + Copy {
    /// Converts a byte array to a u16
    fn u16_from_bytes(self, bytes: [u8; 2]) -> u16;

    /// Converts a byte array to a u32
    fn u32_from_bytes(self, bytes: [u8; 4]) -> u32;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BigEndian;
impl ByteOrder for BigEndian {
    fn u16_from_bytes(self, bytes: [u8; 2]) -> u16 {
        u16::from_be_bytes(bytes)
    }
    fn u32_from_bytes(self, bytes: [u8; 4]) -> u32 {
        u32::from_be_bytes(bytes)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LittleEndian;
impl ByteOrder for LittleEndian {
    fn u16_from_bytes(self, bytes: [u8; 2]) -> u16 {
        u16::from_le_bytes(bytes)
    }
    fn u32_from_bytes(self, bytes: [u8; 4]) -> u32 {
        u32::from_le_bytes(bytes)
    }
}

/// Represents the endianness of the byte order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    LittleEndian,
    BigEndian,
}
impl ByteOrder for Endianness {
    fn u16_from_bytes(self, bytes: [u8; 2]) -> u16 {
        match self {
            Endianness::BigEndian => BigEndian.u16_from_bytes(bytes),
            Endianness::LittleEndian => LittleEndian.u16_from_bytes(bytes),
        }
    }
    fn u32_from_bytes(self, bytes: [u8; 4]) -> u32 {
        match self {
            Endianness::BigEndian => BigEndian.u32_from_bytes(bytes),
            Endianness::LittleEndian => LittleEndian.u32_from_bytes(bytes),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("Unexpected Size for {name}: expected {expected}, got {got}")]
pub struct UnexpectedSize {
    pub name: &'static str,
    pub expected: usize,
    pub got: usize,
}
pub(crate) trait ExtendedByteOrder: ByteOrder {
    /// Converts a byte slice to a u16
    #[allow(dead_code)]
    fn try_u16_from_bytes(self, bytes: &[u8]) -> Result<u16, UnexpectedSize>;

    /// Converts a byte slice to a u32
    fn try_u32_from_bytes(self, bytes: &[u8]) -> Result<u32, UnexpectedSize>;
}
impl<B: ByteOrder> ExtendedByteOrder for B {
    fn try_u16_from_bytes(self, bytes: &[u8]) -> Result<u16, UnexpectedSize> {
        if bytes.len() != 2 {
            return Err(UnexpectedSize {
                name: "u16",
                expected: 2,
                got: bytes.len(),
            });
        }
        Ok(self.u16_from_bytes([bytes[0], bytes[1]]))
    }

    fn try_u32_from_bytes(self, bytes: &[u8]) -> Result<u32, UnexpectedSize> {
        if bytes.len() != 4 {
            return Err(UnexpectedSize {
                name: "u32",
                expected: 4,
                got: bytes.len(),
            });
        }
        Ok(self.u32_from_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_big_endian() {
        let bytes: [u8; 2] = [0x12, 0x34];
        assert_eq!(BigEndian.u16_from_bytes(bytes), 0x1234);
        let bytes: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        assert_eq!(BigEndian.u32_from_bytes(bytes), 0x12345678);
    }
    #[test]
    fn test_little_endian() {
        let bytes: [u8; 2] = [0x34, 0x12];
        assert_eq!(LittleEndian.u16_from_bytes(bytes), 0x1234);
        let bytes: [u8; 4] = [0x78, 0x56, 0x34, 0x12];
        assert_eq!(LittleEndian.u32_from_bytes(bytes), 0x12345678);
    }
}
