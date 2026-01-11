//! Asynchronous reader for PCAP files
use crate::{
    any_reader::AnyPacketHeader,
    byte_order::tokio_async::AsyncReadExt as _,
    pcap_ng::{
        PcapNgParseError,
        blocks::{
            BlockHeader, InterfaceDescriptionBlock, PcapNgBlock, SectionHeaderBlock,
            TokioAsyncBlock,
        },
    },
};
use tokio::io::{AsyncRead, AsyncReadExt};
/// Asynchronous PCAP-NG reader
///
/// Requires the `tokio-async` feature
///
/// ## Notes
///
/// It is recommended to use a buffered reader (e.g., [`tokio::io::BufReader`]) for better performance
/// Due to the nature of this parser it involves many small reads, which can be inefficient on unbuffered readers
#[derive(Debug)]
pub struct AsyncPcapNgReader<R: AsyncRead + Unpin> {
    reader: R,
    /// The current section header block
    current_section: SectionHeaderBlock,
    /// The interfaces described in the file
    ///
    /// Will reset each time a new section header block is read
    interfaces: Vec<InterfaceDescriptionBlock>,
}
impl<R: AsyncRead + Unpin> AsyncPcapNgReader<R> {
    /// Creates a new `SyncPcapReader` from a reader
    /// Returns `Ok(Self)` on success, or `Err` if there was an error
    /// reading the file header
    ///
    /// A buffer is allocated based on the snap length in the file header
    pub async fn new(mut reader: R) -> Result<Self, PcapNgParseError> {
        let header_bytes = reader.read_bytes::<8>().await?;
        let header = BlockHeader::parse_from_bytes(&header_bytes)?;

        let current_section =
            SectionHeaderBlock::async_read_with_header(&mut reader, &header, None).await?;
        Ok(Self {
            reader,
            current_section,
            interfaces: Vec::with_capacity(1),
        })
    }
    pub(crate) fn new_with_section(reader: R, current_section: SectionHeaderBlock) -> Self {
        Self {
            reader,
            current_section,
            interfaces: Vec::with_capacity(1),
        }
    }
    /// Returns the file header of the pcap file
    pub fn current_section(&self) -> &SectionHeaderBlock {
        &self.current_section
    }
    /// Returns the interfaces described in the file
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock] {
        &self.interfaces
    }
    /// Reads the next block from the pcapng file
    ///
    /// This starts by reading 8 bytes for the block header, then reads the rest of the block
    ///
    /// When Ok(None) is returned, it indicates the end of the file has been reached
    pub async fn next_block(&mut self) -> Result<Option<PcapNgBlock>, PcapNgParseError> {
        let mut header_bytes = [0u8; 8];
        match self.reader.read_exact(&mut header_bytes).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Ok(None); // No more blocks
            }
            Err(err) => return Err(PcapNgParseError::IO(err)),
        }
        let header = BlockHeader::parse_from_bytes(&header_bytes)?;

        let result =
            PcapNgBlock::read_async(&mut self.reader, &header, self.current_section.byte_order)
                .await?;
        match &result {
            PcapNgBlock::InterfaceDescription(interface_block) => {
                self.interfaces.push(interface_block.clone());
            }
            PcapNgBlock::SectionHeader(section_header) => {
                self.interfaces.clear();
                self.current_section = section_header.clone();
            }
            _ => {}
        }
        Ok(Some(result))
    }
    /// Reads the next packet from the pcapng file
    ///
    /// If any other block types are encountered, they will be skipped until a packet block is found
    ///
    /// When Ok(None) is returned, it indicates the end of the file has been reached
    pub async fn next_packet(
        &mut self,
    ) -> Result<Option<(AnyPacketHeader, Vec<u8>)>, PcapNgParseError> {
        while let Some(block) = self.next_block().await? {
            match block {
                PcapNgBlock::EnhancedPacket(enhanced_packet) => {
                    return Ok(Some((
                        AnyPacketHeader::PcapNgEnhanced {
                            block_length: enhanced_packet.block_length,
                            original_length: enhanced_packet.original_length,
                            interface_id: enhanced_packet.interface_id,
                            timestamp_high: enhanced_packet.timestamp_high,
                            timestamp_low: enhanced_packet.timestamp_low,
                            captured_length: enhanced_packet.captured_length,
                            options: enhanced_packet.options,
                        },
                        enhanced_packet.content,
                    )));
                }
                PcapNgBlock::SimplePacket(simple_packet) => {
                    return Ok(Some((
                        AnyPacketHeader::PcapNgSimple {
                            block_length: simple_packet.block_length,
                            original_length: simple_packet.original_length,
                        },
                        simple_packet.content,
                    )));
                }
                _ => {
                    // Continue to the next block
                    continue;
                }
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use etherparse::{NetSlice, SlicedPacket};

    use crate::byte_order::Endianness;

    use super::*;
    #[tokio::test]
    async fn read_packets_from_file() -> anyhow::Result<()> {
        let file = tokio::fs::File::open("test_data/ng/test001_le.pcapng").await?;
        let mut reader = AsyncPcapNgReader::new(file).await?;
        assert!(
            reader.current_section.options.is_some(),
            "Section header should have options"
        );
        assert_eq!(
            reader.current_section.byte_order,
            Endianness::LittleEndian,
            "Section header should be little-endian"
        );
        while let Ok(Some(block)) = reader.next_block().await {
            let packet = match block {
                PcapNgBlock::SectionHeader(section_header) => {
                    println!("Section Header: {:?}", section_header);
                    continue;
                }
                PcapNgBlock::InterfaceDescription(interface_block) => {
                    println!("Interface Block: {:?}", interface_block);
                    continue;
                }
                PcapNgBlock::EnhancedPacket(enhanced_packet) => enhanced_packet,
                _ => {
                    panic!("Unexpected block type: {:?}", block);
                }
            };
            println!("---- Packet: (Block Length {}) ----", packet.block_length);
            let parse =
                SlicedPacket::from_ethernet(&packet.content).expect("Failed to parse packet");
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

            println!("---- End of Packet ----");
        }
        Ok(())
    }
}
