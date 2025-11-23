use std::io::Read;

use crate::{
    byte_order::{ByteOrder, Endianness, ExtendedByteOrder},
    link_type::LinkType,
    pcap::PcapParseError,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagicNumber {
    Microsecond,
    Nanosecond,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MagicNumberAndEndianness {
    pub magic_number: MagicNumber,
    pub endianness: Endianness,
}

impl TryFrom<[u8; 4]> for MagicNumberAndEndianness {
    type Error = PcapParseError;

    fn try_from(value: [u8; 4]) -> Result<Self, Self::Error> {
        match value {
            [0xa1, 0xb2, 0xc3, 0xd4] => Ok(Self {
                magic_number: MagicNumber::Microsecond,
                endianness: Endianness::BigEndian,
            }),
            [0xd4, 0xc3, 0xb2, 0xa1] => Ok(Self {
                magic_number: MagicNumber::Microsecond,
                endianness: Endianness::LittleEndian,
            }),
            [0xA1, 0xB2, 0x3C, 0x4D] => Ok(Self {
                magic_number: MagicNumber::Nanosecond,
                endianness: Endianness::BigEndian,
            }),
            [0x4d, 0x3c, 0xb2, 0xa1] => Ok(Self {
                magic_number: MagicNumber::Nanosecond,
                endianness: Endianness::LittleEndian,
            }),
            _ => Err(PcapParseError::InvalidMagicNumber(Some(value))),
        }
    }
}
impl TryFrom<&[u8]> for MagicNumberAndEndianness {
    type Error = PcapParseError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        if value.len() < 4 {
            return Err(PcapParseError::InvalidMagicNumber(None));
        }
        let array: [u8; 4] = value[0..4].try_into()?;
        Self::try_from(array)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    major: u16,
    minor: u16,
}
impl Version {
    /// Parses the version from the bytes
    #[inline(always)]
    fn parse(bytes: &[u8], byte_order: impl ByteOrder) -> Result<Self, PcapParseError> {
        let major = byte_order.u16_from_bytes([bytes[0], bytes[1]]);
        let minor = byte_order.u16_from_bytes([bytes[2], bytes[3]]);
        Ok(Self { major, minor })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapFileHeader {
    /// First 4 bytes are the magic number and endianness
    pub magic_number_and_endianness: MagicNumberAndEndianness,
    /// 4..8
    pub version: Version,
    /// 8..12
    pub timezone: u32,
    /// 12..16
    pub sig_figs: u32,
    /// 16..20
    pub snap_length: u32,
    /// 20..24
    pub link_type: LinkType,
}

impl PcapFileHeader {
    /// Reads the file header from the reader
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, PcapParseError> {
        let mut header = [0u8; 24];
        reader.read_exact(&mut header)?;
        Self::try_from(&header)
    }
}
impl TryFrom<&[u8; 24]> for PcapFileHeader {
    type Error = PcapParseError;

    fn try_from(bytes: &[u8; 24]) -> Result<Self, Self::Error> {
        let magic_number_and_endianness = MagicNumberAndEndianness::try_from(&bytes[0..4])?;

        let version = Version::parse(&bytes[4..8], magic_number_and_endianness.endianness)?;
        let timezone = magic_number_and_endianness
            .endianness
            .try_u32_from_bytes(&bytes[8..12])?;
        let sig_figs = magic_number_and_endianness
            .endianness
            .try_u32_from_bytes(&bytes[12..16])?;
        let snap_length = magic_number_and_endianness
            .endianness
            .try_u32_from_bytes(&bytes[16..20])?;
        let link_type = LinkType::try_from(
            magic_number_and_endianness
                .endianness
                .try_u32_from_bytes(&bytes[20..24])?,
        )?;
        Ok(Self {
            magic_number_and_endianness,
            version,
            timezone,
            sig_figs,
            snap_length,
            link_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_magic_number_and_endianness() {
        let magic_bytes = [0xa1, 0xb2, 0xc3, 0xd4];
        let magic = MagicNumberAndEndianness::try_from(magic_bytes).unwrap();
        assert_eq!(magic.magic_number, MagicNumber::Microsecond);
        assert_eq!(magic.endianness, Endianness::BigEndian);
    }

    #[test]
    fn test_pcap_file_header_read() {
        let file = std::fs::File::open("test_data/test.pcap").expect("Failed to open test.pcap");
        let mut reader = std::io::BufReader::new(file);
        let header = PcapFileHeader::read(&mut reader).expect("Failed to read PCAP header");
        assert_eq!(
            header.magic_number_and_endianness.magic_number,
            MagicNumber::Microsecond
        );
        assert_eq!(
            header.magic_number_and_endianness.endianness,
            Endianness::LittleEndian
        );
        println!("{:?}", header);
    }
}
