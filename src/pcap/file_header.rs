//! PCAP file header representation and parsing
use std::io::{Cursor, Read, Write};

use crate::{
    Version,
    byte_order::{Endianness, ExtendedByteOrder, WriteExt},
    link_type::LinkType,
    pcap::PcapParseError,
};

/// The magic number used to identify pcap files and their endianness
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MagicNumber {
    /// Microsecond Resolution
    #[default]
    Microsecond,
    /// Nanosecond Resolution
    Nanosecond,
}

/// Represents the magic number and endianness of a pcap file
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct MagicNumberAndEndianness {
    /// The magic number identifying the pcap file format and timestamp resolution
    pub magic_number: MagicNumber,
    /// The endianness of the file
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
impl From<MagicNumberAndEndianness> for [u8; 4] {
    fn from(value: MagicNumberAndEndianness) -> Self {
        match (value.magic_number, value.endianness) {
            (MagicNumber::Microsecond, Endianness::LittleEndian) => [0xd4, 0xc3, 0xb2, 0xa1],
            (MagicNumber::Microsecond, Endianness::BigEndian) => [0xa1, 0xb2, 0xc3, 0xd4],
            (MagicNumber::Nanosecond, Endianness::LittleEndian) => [0xA1, 0xB2, 0x3C, 0x4D],
            (MagicNumber::Nanosecond, Endianness::BigEndian) => [0x4d, 0x3c, 0xb2, 0xa1],
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
/// Represents the file header of a pcap file
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcapFileHeader {
    /// First 4 bytes are the magic number and endianness
    pub magic_number_and_endianness: MagicNumberAndEndianness,
    /// The version of the pcap file format
    /// Bytes 4..8
    pub version: Version,
    /// The timezone offset
    /// Bytes 8..12
    pub timezone: u32,
    /// The number of significant figures
    /// Bytes 12..16
    pub sig_figs: u32,
    /// The maximum byte length of captured packets
    ///
    /// Bytes 16..20
    pub snap_length: u32,
    /// The link type of the captured packets
    /// Bytes 20..24
    pub link_type: LinkType,
}
impl Default for PcapFileHeader {
    fn default() -> Self {
        Self {
            magic_number_and_endianness: MagicNumberAndEndianness::default(),
            version: Version::PCAP_VERSION_2_4,
            timezone: Default::default(),
            sig_figs: Default::default(),
            snap_length: Default::default(),
            link_type: Default::default(),
        }
    }
}
impl PcapFileHeader {
    /// Reads the file header from the reader
    pub fn read<R: Read>(reader: &mut R) -> Result<Self, PcapParseError> {
        let mut header = [0u8; 24];
        reader.read_exact(&mut header)?;
        Self::try_from(&header)
    }
    /// Writes the file header to the writer
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        let as_bytes: [u8; 24] = self.into();
        writer.write_all(&as_bytes)?;
        Ok(())
    }
}
impl TryFrom<&[u8; 24]> for PcapFileHeader {
    type Error = PcapParseError;

    fn try_from(bytes: &[u8; 24]) -> Result<Self, Self::Error> {
        let magic_number_and_endianness = MagicNumberAndEndianness::try_from(&bytes[0..4])?;

        let version = Version::parse(&bytes[4..8], magic_number_and_endianness.endianness);
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
impl<'a> From<&'a PcapFileHeader> for [u8; 24] {
    fn from(value: &'a PcapFileHeader) -> Self {
        // It is impossible for these write calls to error out.
        let mut header = Cursor::new([0u8; 24]);
        let magic_number: [u8; 4] = value.magic_number_and_endianness.into();
        let _ = header.write_all(&magic_number);
        let endianness = value.magic_number_and_endianness.endianness;
        let _ = value.version.write(&mut header, endianness);
        let _ = header.write_u32(value.timezone, endianness);
        let _ = header.write_u32(value.sig_figs, endianness);
        let _ = header.write_u32(value.snap_length, endianness);
        let _ = header.write_u32((value.link_type as u16).into(), endianness);
        header.into_inner()
    }
}

impl From<PcapFileHeader> for [u8; 24] {
    fn from(value: PcapFileHeader) -> Self {
        (&value).into()
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

    #[test]
    fn test_header_write() {
        let header = PcapFileHeader {
            magic_number_and_endianness: MagicNumberAndEndianness {
                magic_number: MagicNumber::Microsecond,
                endianness: Endianness::BigEndian,
            },
            version: Version { major: 2, minor: 6 },
            timezone: 1,
            sig_figs: 2,
            snap_length: 100,
            link_type: LinkType::Ethernet,
        };

        let as_bytes: [u8; 24] = header.into();

        let from_bytes =
            PcapFileHeader::try_from(&as_bytes).expect("Unable to parse written header");

        assert_eq!(header, from_bytes)
    }
}
