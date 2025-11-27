use std::io::{self, Seek, Write};

use crate::pcap::{file_header::PcapFileHeader, packet_header::PacketHeader};
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NewPacketHeader {
    pub ts_sec: u32,
    pub ts_usec: u32,
    /// The original length of the packet data
    pub orig_len: Option<u32>,
}
/// A Sync Pcap Writer
///
/// ## Why is Seek Required?
///
/// If you write a packet larger than the snap_length then the header has to be rewritten
pub struct SyncPcapWriter<W: Write + Seek> {
    target: W,
    header: PcapFileHeader,
    /// If a written packet size exceeds snap_len then this will flip to true
    requires_header_rewrite: bool,
}

impl<W: Write + Seek> SyncPcapWriter<W> {
    pub fn new(mut target: W, header: PcapFileHeader) -> Result<Self, io::Error> {
        header.write(&mut target)?;
        Ok(Self {
            target,
            header,
            requires_header_rewrite: false,
        })
    }

    pub fn write_header(
        &mut self,
        header: NewPacketHeader,
        content: &[u8],
    ) -> Result<(), io::Error> {
        let new_header = PacketHeader {
            ts_sec: header.ts_sec,
            ts_usec: header.ts_usec,
            include_len: content.len() as u32,
            orig_len: header.orig_len.unwrap_or(content.len() as u32),
        };
        if new_header.include_len > self.header.snap_length {
            self.requires_header_rewrite = true;
            self.header.snap_length = self.header.snap_length.max(new_header.include_len);
        }

        new_header.write(
            &mut self.target,
            self.header.magic_number_and_endianness.endianness,
        )?;
        self.target.write_all(content)?;
        Ok(())
    }

    pub fn finish(mut self) -> Result<(), io::Error> {
        if !self.requires_header_rewrite {
            return Ok(());
        }

        self.target.seek(io::SeekFrom::Start(0))?;

        self.header.write(&mut self.target)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, time::Duration};

    use chrono::{TimeZone, Utc};
    use etherparse::PacketBuilder;

    use crate::{
        byte_order::Endianness,
        link_type::LinkType,
        pcap::{
            file_header::{MagicNumber, MagicNumberAndEndianness, PcapFileHeader},
            sync::{
                SyncPcapReader,
                writer::{NewPacketHeader, SyncPcapWriter},
            },
        },
    };

    #[test]
    fn test_write() -> anyhow::Result<()> {
        let (actual, expected) = crate::test_helpers::test_files("sync_writer_basic.pcap")?;
        let mut packets_written = Vec::with_capacity(100);

        {
            let file = File::create(&actual)?;

            let mut writer = SyncPcapWriter::new(
                file,
                PcapFileHeader {
                    link_type: LinkType::Ethernet,
                    magic_number_and_endianness: MagicNumberAndEndianness {
                        endianness: Endianness::LittleEndian,
                        magic_number: MagicNumber::Microsecond,
                    },
                    ..Default::default()
                },
            )?;
            let specific_datetime_utc = Utc.with_ymd_and_hms(2025, 11, 27, 10, 30, 0).unwrap();

            let unix_epoch = Utc.timestamp_opt(0, 0).unwrap();
            for i in 0..100 {
                let builder = PacketBuilder::ethernet2([1, 2, 3, 4, 5, 6], [7, 8, 9, 10, 11, 12])
                    .ipv4([192, 168, 1, 1], [192, 168, 1, 2], 20)
                    .udp(21, 1234);

                let payload = [1, 2, 3, 4, 5, 6, 7, 8];

                let mut result = Vec::<u8>::with_capacity(builder.size(payload.len()));
                builder.write(&mut result, &payload).unwrap();
                let time = specific_datetime_utc + Duration::from_secs(i as u64);

                let duration_since_epoch = time.signed_duration_since(unix_epoch);
                let ts_sec = duration_since_epoch.num_seconds() as u32;
                let packet_header = NewPacketHeader {
                    orig_len: None,
                    ts_sec,
                    ts_usec: 0,
                };
                writer.write_header(packet_header, &result)?;
                packets_written.push((ts_sec, result))
            }
            writer.finish()?;
        }

        let mut packet_reader = SyncPcapReader::new(File::open(&actual)?)?;
        let mut written_packets_iter = packets_written.into_iter();
        while let Some((header, bytes)) = packet_reader.next_packet()? {
            let (expected_ts, expected_bytes) = written_packets_iter
                .next()
                .expect("We are short a packet??");

            assert_eq!(
                expected_ts, header.ts_sec,
                "Written ts_sec does not match expected ts_sec"
            );
            assert_eq!(expected_bytes, bytes);
        }
        assert!(
            written_packets_iter.next().is_none(),
            "Not all packets were written"
        );

        crate::test_helpers::do_files_match(actual, expected)?;
        Ok(())
    }
}
