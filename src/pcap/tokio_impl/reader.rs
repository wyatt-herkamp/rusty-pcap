//! Asynchronous reader for PCAP files
use crate::{
    pcap::PcapParseError, pcap::file_header::PcapFileHeader, pcap::packet_header::PacketHeader,
};
use tokio::io::{AsyncRead, AsyncReadExt};
#[derive(Debug)]
pub struct AsyncPcapReader<R: AsyncRead + Unpin> {
    reader: R,
    /// Buffer for packet data
    buffer: Box<[u8]>,
    /// Buffer for packet header
    header_buffer: [u8; 16],
    file_header: PcapFileHeader,
}
impl<R: AsyncRead + Unpin> AsyncPcapReader<R> {
    /// Creates a new `AsyncPcapReader` from a reader
    /// Returns `Ok(Self)` on success, or `Err` if there was an error
    /// reading the file header
    ///
    /// A buffer is allocated based on the snap length in the file header
    pub async fn new(mut reader: R) -> Result<Self, PcapParseError> {
        let mut file_header = [0u8; 24];
        reader.read_exact(&mut file_header).await?;
        let file_header = PcapFileHeader::try_from(&file_header)?;
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
    /// Reads the next packet from the pcap file
    /// Returns `Ok(None)` if there are no more packets to read
    /// Returns `Err` if there was an error reading the packet
    pub async fn next_packet(&mut self) -> Result<Option<(PacketHeader, &[u8])>, PcapParseError> {
        if let Err(err) = self.reader.read_exact(&mut self.header_buffer).await {
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
        // Check if the included length is greater than the snap length
        // This is a sanity check to prevent reading more data than allocated
        if packet_header.include_len > self.file_header.snap_length {
            return Err(PcapParseError::InvalidPacketLength {
                snap_length: self.file_header.snap_length,
                incl_len: packet_header.include_len,
            });
        }
        let mut_buffer: &mut [u8] = &mut self.buffer;
        self.reader
            .read_exact(&mut mut_buffer[0..(packet_header.include_len as usize)])
            .await?;

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
    #[tokio::test]
    async fn read_packets_from_file() {
        let file = tokio::fs::File::open("test_data/test.pcap")
            .await
            .expect("Failed to open test.pcap");
        let mut reader = AsyncPcapReader::new(file)
            .await
            .expect("Failed to create SyncPcapReader");

        while let Ok(Some((header, data))) = reader.next_packet().await {
            println!("Packet Header: {:?}", header);
            let parse = SlicedPacket::from_ethernet(data).expect("Failed to parse packet");
            if let Some(net_slice) = parse.net {
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
            } else {
                println!("Non Packet");
            }
        }
    }
}
