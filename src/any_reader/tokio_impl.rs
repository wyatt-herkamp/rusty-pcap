use std::borrow::Cow;

use tokio::io::AsyncRead;

use crate::{
    PcapFileType,
    any_reader::{AnyPacketHeader, AnyPcapPacket, AnyPcapReaderError},
    byte_order::tokio_async::AsyncReadExt,
    pcap::{file_header::PcapFileHeader, tokio_impl::AsyncPcapReader},
    pcap_ng::{
        blocks::{BlockHeader, SectionHeaderBlock, TokioAsyncBlock},
        tokio_impl::AsyncPcapNgReader,
    },
    utils::tokio_impl::AsyncPeakableReader,
};

#[derive(Debug)]
enum AsyncAnyPcapReaderInner<R: AsyncRead + Unpin> {
    Pcap(AsyncPcapReader<R>),
    PcapNg(AsyncPcapNgReader<R>),
}
impl<R: AsyncRead + Unpin> AsyncAnyPcapReaderInner<R> {
    pub async fn new(mut reader: R) -> Result<Self, AnyPcapReaderError> {
        let mut peakable = AsyncPeakableReader::new(&mut reader, 4).await?;
        let peak = peakable.peak().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Failed to read magic number",
            )
        })?;
        if peak.len() < 4 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Failed to read magic number",
            ))?;
        }

        let first_four_bytes: [u8; 4] = peak[0..4].try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Failed to read magic number",
            )
        })?;
        let Some(file_type) = PcapFileType::from_magic(first_four_bytes) else {
            return Err(AnyPcapReaderError::InvalidPcapFormat);
        };
        match file_type {
            PcapFileType::Pcap => {
                let first_24_bytes = peakable.read_bytes::<24>().await?;
                let header = PcapFileHeader::try_from(&first_24_bytes)?;
                drop(peakable);
                Ok(AsyncAnyPcapReaderInner::Pcap(
                    AsyncPcapReader::new_with_header(reader, header),
                ))
            }
            PcapFileType::PcapNg => {
                let header_bytes = peakable.read_bytes::<8>().await?;
                let header = BlockHeader::parse_from_bytes(&header_bytes)?;

                let current_section =
                    SectionHeaderBlock::async_read_with_header(&mut peakable, &header, None)
                        .await?;
                drop(peakable);
                Ok(AsyncAnyPcapReaderInner::PcapNg(
                    AsyncPcapNgReader::new_with_section(reader, current_section),
                ))
            }
        }
    }
}
/// A reader that can read both pcap and pcapng files
///
/// # When Should I use this?
///
/// When the only requirement is to read packets from either pcap or pcapng files,
/// and you do not need to access file-specific metadata or features.
///
/// # How is is the the file type determined?
///
/// The file type is determined by reading the first four bytes (magic number)
/// of the file. If the magic number matches the pcap format, a pcap reader
/// is created. If it matches the pcapng format, a pcapng reader is created.
/// See [PcapFileType::from_magic] for more information.
#[derive(Debug)]
pub struct AsyncAnyPcapReader<R: AsyncRead + Unpin> {
    inner: AsyncAnyPcapReaderInner<R>,
}
impl<R: AsyncRead + Unpin> AsyncAnyPcapReader<R> {
    /// Creates a new `SyncAnyPcapReader` from a reader
    pub async fn new(reader: R) -> Result<Self, AnyPcapReaderError> {
        let inner = AsyncAnyPcapReaderInner::new(reader).await?;
        Ok(Self { inner })
    }
    /// Reads the next packet from the pcap or pcapng file
    ///
    /// # Why Cow?
    ///
    /// The PcapNg packets do not have a fixed size buffer and each packet is read into a newly allocated Vec<u8>
    pub async fn next_packet(&mut self) -> Result<Option<AnyPcapPacket<'_>>, AnyPcapReaderError> {
        match &mut self.inner {
            AsyncAnyPcapReaderInner::Pcap(pcap_reader) => match pcap_reader.next_packet().await? {
                Some((header, data)) => {
                    Ok(Some((AnyPacketHeader::Pcap(header), Cow::Borrowed(data))))
                }
                None => Ok(None),
            },
            AsyncAnyPcapReaderInner::PcapNg(pcapng_reader) => {
                match pcapng_reader.next_packet().await? {
                    Some((header, data)) => Ok(Some((header, Cow::Owned(data)))),
                    None => Ok(None),
                }
            }
        }
    }
    /// Returns the type of the pcap file
    pub fn file_type(&self) -> PcapFileType {
        match &self.inner {
            AsyncAnyPcapReaderInner::Pcap(_) => PcapFileType::Pcap,
            AsyncAnyPcapReaderInner::PcapNg(_) => PcapFileType::PcapNg,
        }
    }
}
#[cfg(test)]
mod tests {

    use etherparse::{NetSlice, SlicedPacket};

    use crate::{PcapFileType, any_reader::AsyncAnyPcapReader};

    #[tokio::test]
    async fn test_read_any_pcap() {
        let file = tokio::fs::File::open("test_data/test.pcap")
            .await
            .expect("Failed to open test.pcap");
        let mut reader = AsyncAnyPcapReader::new(file)
            .await
            .expect("Failed to create AsyncAnyPcapReader");
        assert_eq!(reader.file_type(), PcapFileType::Pcap);
        while let Ok(Some((header, data))) = reader.next_packet().await {
            println!("Packet Header: {:?}", header);
            let parse = SlicedPacket::from_ethernet(data.as_ref()).expect("Failed to parse packet");
            let Some(net_slice) = parse.net else {
                panic!("Expected a network layer slice, got: {:?}", parse);
            };

            match net_slice {
                NetSlice::Ipv4(ipv4) => {
                    println!("IPv4 Packet: {:?}", ipv4.header());
                    println!("IPv4 Destination: {:?}", ipv4.header().destination_addr());
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
    #[tokio::test]
    async fn test_read_any_pcapng() {
        let file = tokio::fs::File::open("test_data/ng/test001_be.pcapng")
            .await
            .expect("Failed to open test001_be.pcapng");
        let mut reader = AsyncAnyPcapReader::new(file)
            .await
            .expect("Failed to create AsyncAnyPcapReader");
        assert_eq!(reader.file_type(), PcapFileType::PcapNg);
        while let Ok(Some((header, data))) = reader.next_packet().await {
            println!("Packet Header: {:?}", header);
            let parse = SlicedPacket::from_ethernet(data.as_ref()).expect("Failed to parse packet");
            let Some(net_slice) = parse.net else {
                panic!("Expected a network layer slice, got: {:?}", parse);
            };

            match net_slice {
                NetSlice::Ipv4(ipv4) => {
                    println!("IPv4 Packet: {:?}", ipv4.header());
                    println!("IPv4 Destination: {:?}", ipv4.header().destination_addr());
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
