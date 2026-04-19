//! Asynchronous reader for PCAP files using a buffer pool
use crate::{
    Version,
    pcap::{PcapParseError, file_header::PcapFileHeader, packet_header::PacketHeader},
};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader};

use super::buffer_pool::{BufferPool, PooledPacket};

/// An async pcap reader that uses a buffer pool for owned packet buffers.
///
/// Unlike [`AsyncPcapReader`](super::AsyncPcapReader) which returns borrowed slices tied to
/// the reader's lifetime, this reader returns [`PooledPacket`] values that own their buffer
/// and can be sent across task boundaries via channels.
///
/// When a [`PooledPacket`] is dropped, its buffer is automatically returned to the pool.
/// If all pool buffers are in use, [`next_packet`](Self::next_packet) will await until
/// a buffer becomes available.
#[derive(Debug)]
pub struct AsyncPooledPcapReader<R: AsyncRead + Unpin> {
    reader: R,
    header_buffer: [u8; 16],
    file_header: PcapFileHeader,
    pool: BufferPool,
}

impl<R: AsyncRead + Unpin> AsyncPooledPcapReader<BufReader<R>> {
    /// Creates a new `AsyncPooledPcapReader` from a reader.
    ///
    /// A buffer pool of `pool_size` buffers is allocated based on the snap length
    /// in the file header. The reader is wrapped in a `BufReader` with a capacity
    /// of snap length + 16.
    pub async fn new(mut reader: R, pool_size: usize) -> Result<Self, PcapParseError> {
        let mut file_header = [0u8; 24];
        reader.read_exact(&mut file_header).await?;
        let file_header = PcapFileHeader::try_from(&file_header)?;
        let pool = BufferPool::new(pool_size, file_header.snap_length);
        let reader = BufReader::with_capacity(file_header.snap_length as usize + 16, reader);
        Ok(Self {
            reader,
            file_header,
            header_buffer: [0; 16],
            pool,
        })
    }

    /// Creates a new `AsyncPooledPcapReader` from a `BufReader`.
    pub async fn with_buf_reader(
        mut reader: BufReader<R>,
        pool_size: usize,
    ) -> Result<Self, PcapParseError> {
        let mut file_header = [0u8; 24];
        reader.read_exact(&mut file_header).await?;
        let file_header = PcapFileHeader::try_from(&file_header)?;
        let pool = BufferPool::new(pool_size, file_header.snap_length);
        Ok(Self {
            reader,
            file_header,
            header_buffer: [0; 16],
            pool,
        })
    }
}

impl<R: AsyncRead + Unpin> AsyncPooledPcapReader<R> {
    /// Creates a new `AsyncPooledPcapReader` from a reader without wrapping in a `BufReader`.
    pub async fn new_without_buffer(
        mut reader: R,
        pool_size: usize,
    ) -> Result<Self, PcapParseError> {
        let mut file_header = [0u8; 24];
        reader.read_exact(&mut file_header).await?;
        let file_header = PcapFileHeader::try_from(&file_header)?;
        let pool = BufferPool::new(pool_size, file_header.snap_length);
        Ok(Self {
            reader,
            file_header,
            header_buffer: [0; 16],
            pool,
        })
    }

    /// Returns the file header of the pcap file.
    pub fn file_header(&self) -> &PcapFileHeader {
        &self.file_header
    }

    /// Returns the version of the pcap file.
    pub fn version(&self) -> &Version {
        &self.file_header.version
    }

    /// Returns a reference to the buffer pool.
    pub fn pool(&self) -> &BufferPool {
        &self.pool
    }

    /// Reads the next packet from the pcap file, returning an owned [`PooledPacket`].
    ///
    /// If no buffers are available in the pool, this method will await until
    /// a [`PooledPacket`] is dropped elsewhere, returning its buffer to the pool.
    ///
    /// Returns `Ok(None)` at end of file.
    pub async fn next_packet(&mut self) -> Result<Option<PooledPacket>, PcapParseError> {
        // Read the 16-byte packet header before acquiring a buffer.
        // This way EOF is detected without wasting a pool slot.
        if let Err(err) = self.reader.read_exact(&mut self.header_buffer).await {
            if err.kind() == std::io::ErrorKind::UnexpectedEof {
                return Ok(None);
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

        // Acquire a buffer from the pool. Awaits if all buffers are in use.
        let (slot_index, mut buffer) = self.pool.acquire().await.ok_or_else(|| {
            PcapParseError::IO(std::io::Error::other("buffer pool has been shut down"))
        })?;

        let data_len = packet_header.include_len as usize;

        // Read packet data. On error, return the buffer to the pool to avoid leaking it.
        if let Err(err) = self.reader.read_exact(&mut buffer[..data_len]).await {
            self.pool.return_buffer(slot_index, buffer);
            return Err(PcapParseError::IO(err));
        }

        Ok(Some(
            self.pool
                .create_packet(packet_header, data_len, slot_index, buffer),
        ))
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
        let mut reader = AsyncPooledPcapReader::new(file, 8)
            .await
            .expect("Failed to create AsyncPooledPcapReader");

        let mut count = 0;
        while let Ok(Some(packet)) = reader.next_packet().await {
            let data = packet.data();
            let parse = SlicedPacket::from_ethernet(data).expect("Failed to parse packet");
            if let Some(net_slice) = parse.net {
                match net_slice {
                    NetSlice::Ipv4(ipv4) => {
                        println!("IPv4: {:?} -> {:?}", ipv4.header().source_addr(), ipv4.header().destination_addr());
                    }
                    NetSlice::Ipv6(ipv6) => {
                        println!("IPv6: {:?}", ipv6.header());
                    }
                    NetSlice::Arp(arp) => {
                        println!("ARP: {:?}", arp);
                    }
                }
            }
            count += 1;
        }
        assert!(count > 0, "should have read at least one packet");
    }

    #[tokio::test]
    async fn send_packets_through_channel() {
        let file = tokio::fs::File::open("test_data/test.pcap")
            .await
            .expect("Failed to open test.pcap");
        let mut reader = AsyncPooledPcapReader::new(file, 4)
            .await
            .expect("Failed to create AsyncPooledPcapReader");

        let (tx, mut rx) = tokio::sync::mpsc::channel::<PooledPacket>(16);

        // Producer: read all packets and send through channel
        let producer = tokio::spawn(async move {
            let mut sent = 0usize;
            while let Ok(Some(packet)) = reader.next_packet().await {
                if tx.send(packet).await.is_err() {
                    break;
                }
                sent += 1;
            }
            sent
        });

        // Consumer: receive and verify packets
        let mut received = 0usize;
        while let Some(packet) = rx.recv().await {
            // Verify packet data is accessible after being sent through channel
            assert!(!packet.data().is_empty(), "packet data should not be empty");
            assert!(packet.header().include_len > 0);
            received += 1;
        }

        let sent = producer.await.expect("producer task failed");
        assert_eq!(sent, received, "sent and received counts should match");
        assert!(received > 0, "should have received at least one packet");
    }
}
