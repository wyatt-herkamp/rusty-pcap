//! Synchronous PCAP reader and writer
use std::io::Read;
pub mod writer;
use crate::{
    Version,
    pcap::{PcapParseError, file_header::PcapFileHeader, packet_header::PacketHeader},
};
/// A synchronous reader for PCAP files
#[derive(Debug)]
pub struct SyncPcapReader<R: Read> {
    reader: R,
    /// Buffer for packet data
    ///
    /// Allocated to the snap length in the file header
    buffer: Box<[u8]>,
    header_buffer: [u8; 16],
    file_header: PcapFileHeader,
}
impl<R: Read> SyncPcapReader<R> {
    /// Creates a new `SyncPcapReader` from a reader
    /// Returns `Ok(Self)` on success, or `Err` if there was an error
    /// reading the file header
    ///
    /// A buffer is allocated based on the snap length in the file header
    pub fn new(mut reader: R) -> Result<Self, PcapParseError> {
        let file_header = PcapFileHeader::read(&mut reader)?;
        let buffer = vec![0u8; file_header.snap_length as usize].into_boxed_slice();
        Ok(Self {
            reader,
            buffer,
            file_header,
            header_buffer: [0; 16],
        })
    }
    pub(crate) fn new_with_header(reader: R, file_header: PcapFileHeader) -> Self {
        let buffer = vec![0u8; file_header.snap_length as usize].into_boxed_slice();
        Self {
            reader,
            buffer,
            file_header,
            header_buffer: [0; 16],
        }
    }
    /// Returns the file header of the pcap file
    pub fn file_header(&self) -> &PcapFileHeader {
        &self.file_header
    }
    /// Returns the version of the pcap file
    pub fn version(&self) -> &Version {
        &self.file_header.version
    }
    pub fn next_packet(&mut self) -> Result<Option<(PacketHeader, &[u8])>, PcapParseError> {
        if let Err(err) = self.reader.read_exact(&mut self.header_buffer) {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None); // No more packets
            } else {
                return Err(PcapParseError::IO(err));
            }
        }
        let packet_header = PacketHeader::parse_bytes(
            &self.header_buffer,
            self.file_header.magic_number_and_endianness.endianness,
            &self.file_header.version,
        )?;
        if packet_header.include_len > self.file_header.snap_length {
            return Err(PcapParseError::InvalidPacketLength {
                snap_length: self.file_header.snap_length,
                incl_len: packet_header.include_len,
            });
        }
        let mut_buffer: &mut [u8] = &mut self.buffer;
        self.reader
            .read_exact(&mut mut_buffer[0..(packet_header.include_len as usize)])?;

        Ok(Some((
            packet_header,
            &self.buffer[..(packet_header.include_len as usize)],
        )))
    }
}
#[cfg(test)]
mod tests {
    use etherparse::{NetSlice, SlicedPacket};

    use super::*;
    #[test]
    fn read_packets_from_file() {
        let file = std::fs::File::open("test_data/test.pcap").expect("Failed to open test.pcap");
        let mut reader = SyncPcapReader::new(file).expect("Failed to create SyncPcapReader");

        while let Ok(Some((header, data))) = reader.next_packet() {
            println!("Packet Header: {:?}", header);
            let parse = SlicedPacket::from_ethernet(data).expect("Failed to parse packet");
            let Some(net_slice) = parse.net else {
                panic!("Expected a network layer slice, got: {:?}", parse);
            };

            match net_slice {
                NetSlice::Ipv4(ipv4) => {
                    println!("IPv4 Packet: {:?}", ipv4.header());
                    println!("IPv4 Destin: {:?}", ipv4.header().destination_addr());
                    println!("IPv4 Source: {:?}", ipv4.header().source_addr());
                }
                NetSlice::Ipv6(ipv6) => {
                    println!("IPv6 Packet: {:?}", ipv6.header());
                }
                NetSlice::Arp(arp) => {
                    println!("ARP Packet: {:?}", arp);
                }
            }
        }
    }
}
