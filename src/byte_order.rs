//! Byte Order handling for pcap and pcap-ng files

use std::io::{Read, Write};

use thiserror::Error;
/// Returned when the byte order of a pcap or pcap-ng file cannot be determined
/// from its magic number.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("Undetermined byte order")]
pub struct UndertminedByteOrder;
/// Represents a trait for byte order operations
pub trait ByteOrder: Clone + Copy {
    /// Converts a byte array to a u16
    fn u16_from_bytes(self, bytes: [u8; 2]) -> u16;
    /// Converts a u16 to a byte array
    fn u16_to_bytes(self, value: u16) -> [u8; 2];
    /// Converts a byte array to a u32
    fn u32_from_bytes(self, bytes: [u8; 4]) -> u32;
    /// Converts a u32 to a byte array
    fn u32_to_bytes(self, value: u32) -> [u8; 4];
    /// Converts a byte array to a u64
    fn u64_from_bytes(self, bytes: [u8; 8]) -> u64;
}

/// Big-endian byte order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BigEndian;
impl ByteOrder for BigEndian {
    #[inline(always)]
    fn u16_from_bytes(self, bytes: [u8; 2]) -> u16 {
        u16::from_be_bytes(bytes)
    }
    #[inline(always)]
    fn u16_to_bytes(self, value: u16) -> [u8; 2] {
        value.to_be_bytes()
    }
    #[inline(always)]
    fn u32_from_bytes(self, bytes: [u8; 4]) -> u32 {
        u32::from_be_bytes(bytes)
    }
    #[inline(always)]
    fn u32_to_bytes(self, value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }
    #[inline(always)]
    fn u64_from_bytes(self, bytes: [u8; 8]) -> u64 {
        u64::from_be_bytes(bytes)
    }
}
/// Little-endian byte order
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LittleEndian;
impl ByteOrder for LittleEndian {
    #[inline(always)]
    fn u16_from_bytes(self, bytes: [u8; 2]) -> u16 {
        u16::from_le_bytes(bytes)
    }
    #[inline(always)]
    fn u16_to_bytes(self, value: u16) -> [u8; 2] {
        value.to_le_bytes()
    }
    #[inline(always)]
    fn u32_from_bytes(self, bytes: [u8; 4]) -> u32 {
        u32::from_le_bytes(bytes)
    }
    #[inline(always)]
    fn u32_to_bytes(self, value: u32) -> [u8; 4] {
        value.to_le_bytes()
    }
    #[inline(always)]
    fn u64_from_bytes(self, bytes: [u8; 8]) -> u64 {
        u64::from_le_bytes(bytes)
    }
}

/// Represents the endianness of the byte order
///
/// ## Note
///
/// `Default` is based on the host architecture, so it should not be relied on
/// in tests — specify [`BigEndian`] or [`LittleEndian`] explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    /// Little-endian byte order
    LittleEndian,
    /// Big-endian byte order
    BigEndian,
}
#[cfg(target_endian = "little")]
#[allow(clippy::derivable_impls)]
impl Default for Endianness {
    fn default() -> Self {
        Endianness::LittleEndian
    }
}

#[cfg(target_endian = "big")]
#[allow(clippy::derivable_impls)]
impl Default for Endianness {
    fn default() -> Self {
        Endianness::BigEndian
    }
}
impl ByteOrder for Endianness {
    #[inline(always)]
    fn u16_from_bytes(self, bytes: [u8; 2]) -> u16 {
        match self {
            Endianness::BigEndian => BigEndian.u16_from_bytes(bytes),
            Endianness::LittleEndian => LittleEndian.u16_from_bytes(bytes),
        }
    }
    #[inline(always)]
    fn u16_to_bytes(self, value: u16) -> [u8; 2] {
        match self {
            Endianness::BigEndian => BigEndian.u16_to_bytes(value),
            Endianness::LittleEndian => LittleEndian.u16_to_bytes(value),
        }
    }
    #[inline(always)]
    fn u32_from_bytes(self, bytes: [u8; 4]) -> u32 {
        match self {
            Endianness::BigEndian => BigEndian.u32_from_bytes(bytes),
            Endianness::LittleEndian => LittleEndian.u32_from_bytes(bytes),
        }
    }
    #[inline(always)]
    fn u32_to_bytes(self, value: u32) -> [u8; 4] {
        match self {
            Endianness::BigEndian => BigEndian.u32_to_bytes(value),
            Endianness::LittleEndian => LittleEndian.u32_to_bytes(value),
        }
    }
    #[inline(always)]
    fn u64_from_bytes(self, bytes: [u8; 8]) -> u64 {
        match self {
            Endianness::BigEndian => BigEndian.u64_from_bytes(bytes),
            Endianness::LittleEndian => LittleEndian.u64_from_bytes(bytes),
        }
    }
}

/// Returned when a slice of bytes does not match the expected size for the
/// integer type being parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("Unexpected Size for {name}: expected {expected}, got {got}")]
pub struct UnexpectedSize {
    /// Name of the value being parsed (e.g. `"u16"`)
    pub name: &'static str,
    /// Number of bytes that were expected
    pub expected: usize,
    /// Number of bytes that were actually received
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
    #[inline(always)]
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
    #[inline(always)]
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
/// Extension trait for [`Read`] adding byte-order-aware integer reads.
pub trait ReadExt {
    /// Reads a u16 from the reader
    fn read_u16<B: ByteOrder>(&mut self, byte_order: B) -> Result<u16, std::io::Error>;

    /// Reads a u32 from the reader
    fn read_u32<B: ByteOrder>(&mut self, byte_order: B) -> Result<u32, std::io::Error>;
    /// Has nothing to do with byte order, just reads a fixed number of bytes
    ///
    /// But exists for simplicity
    fn read_bytes<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], std::io::Error>;
}
impl<R: Read> ReadExt for R {
    fn read_u16<B: ByteOrder>(&mut self, byte_order: B) -> Result<u16, std::io::Error> {
        let mut buffer = [0u8; 2];
        self.read_exact(&mut buffer)?;
        Ok(byte_order.u16_from_bytes(buffer))
    }
    fn read_u32<B: ByteOrder>(&mut self, byte_order: B) -> Result<u32, std::io::Error> {
        let mut buffer = [0u8; 4];
        self.read_exact(&mut buffer)?;
        Ok(byte_order.u32_from_bytes(buffer))
    }
    #[inline(always)]
    fn read_bytes<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], std::io::Error> {
        let mut buffer = [0u8; SIZE];
        self.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

/// Extension trait for [`Write`] adding byte-order-aware integer writes.
pub trait WriteExt {
    /// Writes a u16 to the writer
    fn write_u16<B: ByteOrder>(&mut self, value: u16, byte_order: B) -> Result<(), std::io::Error>;

    /// Writes a u32 to the writer
    fn write_u32<B: ByteOrder>(&mut self, value: u32, byte_order: B) -> Result<(), std::io::Error>;
}
impl<R: Write> WriteExt for R {
    fn write_u16<B: ByteOrder>(&mut self, value: u16, byte_order: B) -> Result<(), std::io::Error> {
        let value = byte_order.u16_to_bytes(value);
        self.write_all(&value)?;
        Ok(())
    }
    fn write_u32<B: ByteOrder>(&mut self, value: u32, byte_order: B) -> Result<(), std::io::Error> {
        let value = byte_order.u32_to_bytes(value);
        self.write_all(&value)?;
        Ok(())
    }
}

/// Async byte-order utilities, gated on the `tokio-async` feature.
#[cfg(feature = "tokio-async")]
pub mod tokio_async {
    use tokio::io::{AsyncRead, AsyncReadExt as _};

    use crate::byte_order::ByteOrder;

    /// Async counterpart to [`super::ReadExt`] for [`AsyncRead`] types.
    pub trait AsyncReadExt {
        /// Reads a u16 from the reader
        fn read_u16<B: ByteOrder>(
            &mut self,
            byte_order: B,
        ) -> impl Future<Output = Result<u16, std::io::Error>>;

        /// Reads a u32 from the reader
        fn read_u32<B: ByteOrder>(
            &mut self,
            byte_order: B,
        ) -> impl Future<Output = Result<u32, std::io::Error>>;
        /// Has nothing to do with byte order, just reads a fixed number of bytes
        ///
        /// But exists for simplicity
        fn read_bytes<const SIZE: usize>(
            &mut self,
        ) -> impl Future<Output = Result<[u8; SIZE], std::io::Error>>;
    }
    impl<R: AsyncRead + Unpin> AsyncReadExt for R {
        async fn read_u16<B: ByteOrder>(&mut self, byte_order: B) -> Result<u16, std::io::Error> {
            let mut buffer = [0u8; 2];
            self.read_exact(&mut buffer).await?;
            Ok(byte_order.u16_from_bytes(buffer))
        }
        async fn read_u32<B: ByteOrder>(&mut self, byte_order: B) -> Result<u32, std::io::Error> {
            let mut buffer = [0u8; 4];
            self.read_exact(&mut buffer).await?;
            Ok(byte_order.u32_from_bytes(buffer))
        }
        async fn read_bytes<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], std::io::Error> {
            let mut buffer = [0u8; SIZE];
            self.read_exact(&mut buffer).await?;
            Ok(buffer)
        }
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
