use std::{borrow::Cow, io::Read};

use thiserror::Error;

use crate::{
    PcapFileType,
    pcap::{PcapParseError, file_header::PcapFileHeader, sync::SyncPcapReader},
    pcap_ng::{PcapNgParseError, blocks::SectionHeaderBlock, sync::SyncPcapNgReader},
    utils::PeakableReader,
};
mod header;
pub use header::*;

#[derive(Debug, Error)]
pub enum AnyPcapReaderError {
    #[error("Invalid pcap format")]
    InvalidPcapFormat,
    #[error(transparent)]
    PcapError(#[from] PcapParseError),
    #[error(transparent)]
    PcapNgError(#[from] PcapNgParseError),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}
#[derive(Debug)]
enum SyncAnyPcapReaderInner<R: std::io::Read> {
    Pcap(SyncPcapReader<R>),
    PcapNg(SyncPcapNgReader<R>),
}
impl<R: Read> SyncAnyPcapReaderInner<R> {
    pub fn new(mut reader: R) -> Result<Self, AnyPcapReaderError> {
        let mut peakable = PeakableReader::new(&mut reader, 4)?;
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
                let header = PcapFileHeader::read(&mut peakable)?;
                drop(peakable);
                Ok(SyncAnyPcapReaderInner::Pcap(
                    SyncPcapReader::new_with_header(reader, header),
                ))
            }
            PcapFileType::PcapNg => {
                let current_section = SectionHeaderBlock::read_from_reader(&mut peakable)?;
                drop(peakable);
                Ok(SyncAnyPcapReaderInner::PcapNg(
                    SyncPcapNgReader::new_with_section(reader, current_section),
                ))
            }
        }
    }
}
pub type AnyPcapPacket<'a> = (AnyPacketHeader, Cow<'a, [u8]>);
/// A reader that can read both pcap and pcapng files
///
/// # When Should I use this?
///
/// When the only requirement is to read packets from either pcap or pcapng files,
/// and you do not need to access file-specific metadata or features.
///
/// # Where is AsyncAnyPcapReader?
///
/// This library currently only provides sync pcapng reading functionality.
/// Async pcapng reading functionality will be added in a future release.
///
/// # How is is the the file type determined?
///
/// The file type is determined by reading the first four bytes (magic number)
/// of the file. If the magic number matches the pcap format, a pcap reader
/// is created. If it matches the pcapng format, a pcapng reader is created.
/// See [PcapFileType::from_magic] for more information.
#[derive(Debug)]
pub struct SyncAnyPcapReader<R: std::io::Read> {
    inner: SyncAnyPcapReaderInner<R>,
}
impl<R: Read> SyncAnyPcapReader<R> {
    /// Creates a new `SyncAnyPcapReader` from a reader
    pub fn new(reader: R) -> Result<Self, AnyPcapReaderError> {
        let inner = SyncAnyPcapReaderInner::new(reader)?;
        Ok(Self { inner })
    }
    /// Reads the next packet from the pcap or pcapng file
    ///
    /// # Why Cow?
    ///
    /// The PcapNg packets do not have a fixed size buffer and each packet is read into a newly allocated Vec<u8>
    pub fn next_packet(&mut self) -> Result<Option<AnyPcapPacket<'_>>, AnyPcapReaderError> {
        match &mut self.inner {
            SyncAnyPcapReaderInner::Pcap(pcap_reader) => match pcap_reader.next_packet()? {
                Some((header, data)) => {
                    Ok(Some((AnyPacketHeader::Pcap(header), Cow::Borrowed(data))))
                }
                None => Ok(None),
            },
            SyncAnyPcapReaderInner::PcapNg(pcapng_reader) => match pcapng_reader.next_packet()? {
                Some((header, data)) => Ok(Some((header, Cow::Owned(data)))),
                None => Ok(None),
            },
        }
    }
    /// Returns the type of the pcap file
    pub fn file_type(&self) -> PcapFileType {
        match &self.inner {
            SyncAnyPcapReaderInner::Pcap(_) => PcapFileType::Pcap,
            SyncAnyPcapReaderInner::PcapNg(_) => PcapFileType::PcapNg,
        }
    }
}
#[cfg(test)]
mod tests {

    use etherparse::{NetSlice, SlicedPacket};

    use crate::{PcapFileType, any_reader::SyncAnyPcapReader};

    #[test]
    fn test_read_any_pcap() {
        let file = std::fs::File::open("test_data/test.pcap").expect("Failed to open test.pcap");
        let mut reader = SyncAnyPcapReader::new(file).expect("Failed to create SyncPcapReader");
        assert_eq!(reader.file_type(), PcapFileType::Pcap);
        while let Ok(Some((header, data))) = reader.next_packet() {
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
    #[test]
    fn test_read_any_pcapng() {
        let file = std::fs::File::open("test_data/ng/test001_be.pcapng")
            .expect("Failed to open test001_be.pcapng");
        let mut reader = SyncAnyPcapReader::new(file).expect("Failed to create SyncPcapReader");
        assert_eq!(reader.file_type(), PcapFileType::PcapNg);
        while let Ok(Some((header, data))) = reader.next_packet() {
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
