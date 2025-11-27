use std::io::{Cursor, Read, Write};

use crate::{
    byte_order::{Endianness, ReadExt, WriteExt},
    pcap::PcapHeader,
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
    pub fn read<R: Read>(reader: &mut R, endianness: Endianness) -> Result<Self, PcapHeader> {
        let mut header = [0u8; 16];
        reader.read_exact(&mut header)?;
        Self::parse_bytes(&header, endianness)
    }
    #[inline(always)]
    pub fn parse_bytes(bytes: &[u8; 16], endianness: Endianness) -> Result<Self, PcapHeader> {
        let mut cursor = Cursor::new(bytes);
        let ts = cursor.read_u32(endianness)?;
        let ts_usec = cursor.read_u32(endianness)?;
        let include_len = cursor.read_u32(endianness)?;
        let orig_len = cursor.read_u32(endianness)?;
        Ok(Self {
            ts_sec: ts,
            ts_usec,
            include_len,
            orig_len,
        })
    }
    pub fn write<W: Write>(
        &self,
        writer: &mut W,
        endianness: Endianness,
    ) -> Result<(), std::io::Error> {
        writer.write_u32(self.ts_sec, endianness)?;
        writer.write_u32(self.ts_usec, endianness)?;
        writer.write_u32(self.include_len, endianness)?;
        writer.write_u32(self.orig_len, endianness)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{io::Cursor};

    use chrono::{TimeZone, Utc};

    use crate::{byte_order::Endianness, pcap::packet_header::PacketHeader};

    #[test]
    fn write_test() -> anyhow::Result<()> {
        let specific_datetime_utc = Utc.with_ymd_and_hms(2025, 11, 27, 10, 30, 0).unwrap();

        let duration_since_epoch =
            specific_datetime_utc.signed_duration_since(Utc.timestamp_opt(0, 0).unwrap());

        let as_secs = duration_since_epoch.num_seconds() as u32;
        let num_nanos = duration_since_epoch.subsec_nanos() as u32;
        let mut target: [u8; 16] = [0; 16];
        let header = PacketHeader {
            ts_sec: as_secs,
            ts_usec: num_nanos,
            include_len: 100,
            orig_len: 100,
        };
        {
            let mut writer: Cursor<&mut [u8]> = Cursor::new(&mut target);
            header.write(&mut writer, Endianness::BigEndian)?;
        }

        let result = PacketHeader::parse_bytes(&target, Endianness::BigEndian)?;
        println!("{result:?}");
        assert_eq!(result, header);
        Ok(())
    }
}
