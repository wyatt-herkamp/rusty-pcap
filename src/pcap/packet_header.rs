//! Packet header representation and parsing for pcap files
use std::{
    io::{Cursor, Read, Write},
    time::{SystemTime, SystemTimeError},
};

use crate::{
    Version,
    byte_order::{Endianness, ReadExt, WriteExt},
    pcap::PcapHeader,
};
/// Represents the timestamp of a packet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PacketTimestamp {
    /// Seconds since epoch
    pub seconds: u32,
    /// If microseconds resolution - microseconds part
    /// If nanoseconds resolution - nanoseconds part
    pub usec: u32,
}
impl TryFrom<SystemTime> for PacketTimestamp {
    type Error = SystemTimeError;

    fn try_from(value: SystemTime) -> Result<Self, Self::Error> {
        let duration_since_epoch = value.duration_since(SystemTime::UNIX_EPOCH)?;
        Ok(Self {
            seconds: duration_since_epoch.as_secs() as u32,
            usec: duration_since_epoch.subsec_nanos(),
        })
    }
}
#[cfg(feature = "chrono")]
mod _chrono_impl {
    use chrono::{DateTime, NaiveDateTime};

    use crate::pcap::file_header::MagicNumber;

    use super::PacketTimestamp;
    impl PacketTimestamp {
        pub fn to_chrono_naive_datetime(&self, resolution: MagicNumber) -> Option<NaiveDateTime> {
            match resolution {
                MagicNumber::Microsecond => {
                    DateTime::from_timestamp(self.seconds as i64, self.usec * 1000)
                        .map(|x| x.naive_utc())
                }
                MagicNumber::Nanosecond => {
                    DateTime::from_timestamp(self.seconds as i64, self.usec).map(|x| x.naive_utc())
                }
            }
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketHeader {
    pub timestamp: PacketTimestamp,
    /// The length of the packet data included in the file
    pub include_len: u32,
    /// The original length of the packet data
    pub orig_len: u32,
}

impl PacketHeader {
    pub fn new(timestamp: PacketTimestamp, incl_len: u32, orig_len: u32) -> Self {
        Self {
            timestamp,
            include_len: incl_len,
            orig_len,
        }
    }
    /// Reads the packet header from the reader
    /// Returns `Ok(Self)` on success, or `Err` if there was an error
    /// reading the packet header
    /// The endianness is used to determine how to read the bytes
    #[inline(always)]
    pub fn read<R: Read>(
        reader: &mut R,
        endianness: Endianness,
        version: &Version,
    ) -> Result<Self, PcapHeader> {
        let mut header = [0u8; 16];
        reader.read_exact(&mut header)?;
        Self::parse_bytes(&header, endianness, version)
    }
    #[inline(always)]
    pub fn parse_bytes(
        bytes: &[u8; 16],
        endianness: Endianness,
        version: &Version,
    ) -> Result<Self, PcapHeader> {
        let mut cursor = Cursor::new(bytes);
        let ts = cursor.read_u32(endianness)?;
        let ts_usec = cursor.read_u32(endianness)?;
        let (include_len, orig_len) = if version < &Version::PCAP_VERSION_2_3 {
            let orig_len = cursor.read_u32(endianness)?;
            let include_len = cursor.read_u32(endianness)?;
            (include_len, orig_len)
        } else {
            let include_len = cursor.read_u32(endianness)?;
            let orig_len = cursor.read_u32(endianness)?;
            (include_len, orig_len)
        };
        Ok(Self {
            timestamp: PacketTimestamp {
                seconds: ts,
                usec: ts_usec,
            },
            include_len,
            orig_len,
        })
    }
    pub fn write<W: Write>(
        &self,
        writer: &mut W,
        endianness: Endianness,
        version: &Version,
    ) -> Result<(), std::io::Error> {
        writer.write_u32(self.timestamp.seconds, endianness)?;
        writer.write_u32(self.timestamp.usec, endianness)?;
        if version < &Version::PCAP_VERSION_2_3 {
            writer.write_u32(self.orig_len, endianness)?;
            writer.write_u32(self.include_len, endianness)?;
            return Ok(());
        } else {
            writer.write_u32(self.include_len, endianness)?;
            writer.write_u32(self.orig_len, endianness)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use chrono::{TimeZone, Utc};

    use crate::{
        Version,
        byte_order::Endianness,
        pcap::packet_header::{PacketHeader, PacketTimestamp},
    };

    #[test]
    fn write_test() -> anyhow::Result<()> {
        let specific_datetime_utc = Utc.with_ymd_and_hms(2025, 11, 27, 10, 30, 0).unwrap();

        let duration_since_epoch =
            specific_datetime_utc.signed_duration_since(Utc.timestamp_opt(0, 0).unwrap());

        let as_secs = duration_since_epoch.num_seconds() as u32;
        let num_nanos = duration_since_epoch.subsec_nanos() as u32;
        let mut target: [u8; 16] = [0; 16];
        let header = PacketHeader {
            timestamp: crate::pcap::packet_header::PacketTimestamp {
                seconds: as_secs,
                usec: num_nanos,
            },
            include_len: 100,
            orig_len: 100,
        };
        {
            let mut writer: Cursor<&mut [u8]> = Cursor::new(&mut target);
            header.write(
                &mut writer,
                Endianness::BigEndian,
                &Version::PCAP_VERSION_2_4,
            )?;
        }

        let result =
            PacketHeader::parse_bytes(&target, Endianness::BigEndian, &Version::PCAP_VERSION_2_4)?;
        println!("{result:?}");
        assert_eq!(result, header);
        Ok(())
    }

    #[test]
    fn test_len_order() {
        let packet_header = PacketHeader {
            timestamp: PacketTimestamp::default(),
            include_len: 1500,
            orig_len: 2000,
        };
        let mut buffer: [u8; 16] = [0; 16];
        {
            let mut writer: Cursor<&mut [u8]> = Cursor::new(&mut buffer);
            packet_header
                .write(
                    &mut writer,
                    Endianness::LittleEndian,
                    &Version::PCAP_VERSION_2_4,
                )
                .unwrap();
        }
        let parsed_header = PacketHeader::parse_bytes(
            &buffer,
            Endianness::LittleEndian,
            &Version::PCAP_VERSION_2_4,
        )
        .unwrap();
        assert_eq!(parsed_header.include_len, 1500);
        assert_eq!(parsed_header.orig_len, 2000);

        let parsed_header_v2_2 = PacketHeader::parse_bytes(
            &buffer,
            Endianness::LittleEndian,
            &Version { major: 2, minor: 2 },
        )
        .unwrap();
        assert_eq!(parsed_header_v2_2.orig_len, 1500);
        assert_eq!(parsed_header_v2_2.include_len, 2000);
    }
    #[test]
    fn test_len_order_older() {
        let packet_header = PacketHeader {
            timestamp: PacketTimestamp::default(),
            include_len: 1500,
            orig_len: 2000,
        };
        let version = Version { major: 2, minor: 2 };
        let mut buffer: [u8; 16] = [0; 16];
        {
            let mut writer: Cursor<&mut [u8]> = Cursor::new(&mut buffer);
            packet_header
                .write(&mut writer, Endianness::LittleEndian, &version)
                .unwrap();
        }
        let parsed_header = PacketHeader::parse_bytes(
            &buffer,
            Endianness::LittleEndian,
            &Version::PCAP_VERSION_2_4,
        )
        .unwrap();
        assert_eq!(parsed_header.include_len, 2000);
        assert_eq!(parsed_header.orig_len, 1500);

        let parsed_header_v2_2 =
            PacketHeader::parse_bytes(&buffer, Endianness::LittleEndian, &version).unwrap();
        assert_eq!(parsed_header_v2_2.include_len, 1500);
        assert_eq!(parsed_header_v2_2.orig_len, 2000);
    }
}
