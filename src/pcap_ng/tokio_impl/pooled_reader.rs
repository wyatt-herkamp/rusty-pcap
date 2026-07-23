//! Asynchronous pcap-ng reader that uses a buffer pool for owned packet buffers.
use std::num::{NonZeroU32, NonZeroUsize};

use tokio::io::{AsyncRead, AsyncReadExt};

use crate::{
    Version,
    any_reader::AnyPacketHeader,
    buffer_pool::{BufferPool, PooledPacket},
    byte_order::{ByteOrder, Endianness},
    pcap_ng::{
        PcapNgParseError,
        blocks::{
            BlockHeader, InterfaceDescriptionBlock, PcapNgBlock, SectionHeaderBlock,
            TokioAsyncBlock,
        },
        options::BlockOptions,
        pad_length_to_32_bytes,
    },
};

/// Default nominal buffer size (bytes) used by
/// [`AsyncPooledPcapNgReader::with_default_buffer_size`].
///
/// Matches the scratch buffer default of the borrowed [`AsyncPcapNgReader`](super::AsyncPcapNgReader).
pub const DEFAULT_BUFFER_SIZE: u32 = 65536;

/// [`DEFAULT_BUFFER_SIZE`] as a [`NonZeroU32`], validated at compile time.
const DEFAULT_BUFFER_SIZE_NZ: NonZeroU32 = match NonZeroU32::new(DEFAULT_BUFFER_SIZE) {
    Some(v) => v,
    None => panic!("DEFAULT_BUFFER_SIZE must be non-zero"),
};

/// An owned pcap-ng packet backed by a pooled buffer.
///
/// This is [`PooledPacket`] specialized to [`AnyPacketHeader`], the owned header
/// enum produced for Enhanced and Simple Packet Blocks.
pub type PooledNgPacket = PooledPacket<AnyPacketHeader>;

/// An async pcap-ng reader that returns owned [`PooledNgPacket`] values from a
/// buffer pool.
///
/// Unlike [`AsyncPcapNgReader`](super::AsyncPcapNgReader), whose `next_packet`
/// borrows an internal scratch buffer, this reader hands back packets that own
/// their buffer and are `Send + Sync`, so they can be moved across task
/// boundaries via channels. When a packet is dropped its buffer returns to the
/// pool automatically; if all buffers are checked out,
/// [`next_packet`](Self::next_packet) awaits until one is returned, giving
/// natural backpressure bounded by the pool size.
///
/// ## Buffer sizing
///
/// pcap-ng has no global snap length (it is a per-interface property discovered
/// after the section header), so the pool is created with a *nominal*
/// `buffer_size`. If a captured packet is larger than the current buffer, the
/// reader transparently grows that buffer to fit rather than failing — the grown
/// buffer returns to its pool slot on drop, so the pool adapts over time. This
/// means total pool memory can exceed `buffer_size * pool_size` when large
/// packets appear, and the first oversized read for a slot pays a reallocation.
///
/// ## Notes
///
/// It is recommended to use a buffered reader (e.g., [`tokio::io::BufReader`])
/// for better performance, as parsing involves many small reads.
#[derive(Debug)]
pub struct AsyncPooledPcapNgReader<R: AsyncRead + Unpin> {
    reader: R,
    /// The current section header block.
    current_section: SectionHeaderBlock,
    /// The interfaces described in the file. Reset on each new section header.
    interfaces: Vec<InterfaceDescriptionBlock>,
    /// Reusable scratch buffer for non-packet blocks that are parsed and skipped.
    scratch: Vec<u8>,
    /// Pool of reusable, owned packet buffers.
    pool: BufferPool,
}

impl<R: AsyncRead + Unpin> AsyncPooledPcapNgReader<R> {
    /// Creates a new `AsyncPooledPcapNgReader`, reading the initial section
    /// header block from `reader`.
    ///
    /// # Arguments
    /// * `reader` - The async reader to read pcap-ng data from.
    /// * `pool_size` - The number of packet buffers to allocate in the pool.
    /// * `buffer_size` - The initial (nominal) size of each pool buffer. Buffers
    ///   grow on demand for larger packets; see the type-level docs.
    pub async fn new(
        mut reader: R,
        pool_size: NonZeroUsize,
        buffer_size: NonZeroU32,
    ) -> Result<Self, PcapNgParseError> {
        let mut header_bytes = [0u8; 8];
        reader.read_exact(&mut header_bytes).await?;
        let header = BlockHeader::parse_from_bytes(&header_bytes)?;

        let mut scratch = vec![0u8; buffer_size.get() as usize];
        let current_section =
            SectionHeaderBlock::async_read_with_header(&mut reader, &header, None, &mut scratch)
                .await?;
        let pool = BufferPool::new(pool_size, buffer_size.get());
        Ok(Self {
            reader,
            current_section,
            interfaces: Vec::with_capacity(1),
            scratch,
            pool,
        })
    }

    /// Creates a new `AsyncPooledPcapNgReader` using [`DEFAULT_BUFFER_SIZE`] for
    /// the nominal pool buffer size.
    pub async fn with_default_buffer_size(
        reader: R,
        pool_size: NonZeroUsize,
    ) -> Result<Self, PcapNgParseError> {
        Self::new(reader, pool_size, DEFAULT_BUFFER_SIZE_NZ).await
    }

    /// Returns the current section header block.
    pub fn current_section(&self) -> &SectionHeaderBlock {
        &self.current_section
    }

    /// Returns the version of the pcap-ng file (from the current section header).
    pub fn version(&self) -> &Version {
        &self.current_section.version
    }

    /// Returns the interfaces described so far in the current section.
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock] {
        &self.interfaces
    }

    /// Returns a reference to the buffer pool (e.g. to `recycle` batches).
    pub fn pool(&self) -> &BufferPool {
        &self.pool
    }

    /// Reads the next packet from the pcap-ng file, returning an owned
    /// [`PooledNgPacket`].
    ///
    /// Enhanced and Simple Packet Blocks are returned; any other block type is
    /// parsed (to keep section/interface state current) and skipped. Returns
    /// `Ok(None)` at end of file.
    ///
    /// If all pool buffers are in use, this awaits until one is returned.
    pub async fn next_packet(&mut self) -> Result<Option<PooledNgPacket>, PcapNgParseError> {
        loop {
            let mut header_bytes = [0u8; 8];
            match self.reader.read_exact(&mut header_bytes).await {
                Ok(_) => {}
                Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(err) => return Err(PcapNgParseError::IO(err)),
            }
            let header = BlockHeader::parse_from_bytes(&header_bytes)?;
            let byte_order = self.current_section.byte_order;

            match header.block_id_as_u32(byte_order) {
                // Enhanced Packet Block
                6 => {
                    return self
                        .read_enhanced_packet(&header, byte_order)
                        .await
                        .map(Some);
                }
                // Simple Packet Block
                3 => return self.read_simple_packet(&header, byte_order).await.map(Some),
                // Any other block: parse and skip, keeping section/interface state.
                _ => {
                    let block = PcapNgBlock::read_async(
                        &mut self.reader,
                        &header,
                        byte_order,
                        &mut self.scratch,
                    )
                    .await?;
                    match block {
                        PcapNgBlock::InterfaceDescription(interface_block) => {
                            self.interfaces.push(interface_block);
                        }
                        PcapNgBlock::SectionHeader(section_header) => {
                            self.interfaces.clear();
                            self.current_section = section_header;
                        }
                        _ => {}
                    }
                    continue;
                }
            }
        }
    }

    /// Reads an Enhanced Packet Block body (the 8-byte block header has already
    /// been consumed) into a pooled buffer.
    async fn read_enhanced_packet(
        &mut self,
        header: &BlockHeader,
        byte_order: Endianness,
    ) -> Result<PooledNgPacket, PcapNgParseError> {
        // Fixed 20-byte body read before acquiring a buffer so EOF / validation
        // errors never waste a pool slot.
        let mut fixed = [0u8; 20];
        self.reader.read_exact(&mut fixed).await?;
        let interface_id = byte_order.u32_from_bytes([fixed[0], fixed[1], fixed[2], fixed[3]]);
        let timestamp_high = byte_order.u32_from_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let timestamp_low = byte_order.u32_from_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]);
        let captured_length =
            byte_order.u32_from_bytes([fixed[12], fixed[13], fixed[14], fixed[15]]);
        let original_length =
            byte_order.u32_from_bytes([fixed[16], fixed[17], fixed[18], fixed[19]]);

        let block_length = header.block_length_as_u32(byte_order);
        let captured = captured_length as usize;
        let padded = pad_length_to_32_bytes(captured);

        // EPB minimum_size = 32 = 8 (BlockHeader) + 20 (fixed) + 4 (footer).
        // Guard against a corrupt block length that would desync the stream.
        let minimum = 32 + padded;
        if (block_length as usize) < minimum {
            return Err(PcapNgParseError::MinimumSizeNotMet(
                minimum,
                block_length as usize,
            ));
        }
        let options_budget = (block_length as usize) - minimum;

        let (slot_index, mut buffer) = self.acquire().await?;
        // Everything after acquire must route errors through return_buffer.
        let result = async {
            read_into(&mut self.reader, &mut buffer, captured, padded - captured).await?;
            let options = BlockOptions::read_async_bounded_option(
                &mut self.reader,
                byte_order,
                options_budget,
            )
            .await?;
            // Footer (trailing block length).
            let mut footer = [0u8; 4];
            self.reader.read_exact(&mut footer).await?;
            Ok::<_, PcapNgParseError>(options)
        }
        .await;

        match result {
            Ok(options) => {
                let any_header = AnyPacketHeader::PcapNgEnhanced {
                    block_length,
                    interface_id,
                    timestamp_high,
                    timestamp_low,
                    captured_length,
                    original_length,
                    options,
                };
                Ok(self
                    .pool
                    .create_packet(any_header, captured, slot_index, buffer))
            }
            Err(err) => {
                self.pool.return_buffer(slot_index, buffer);
                Err(err)
            }
        }
    }

    /// Reads a Simple Packet Block body (the 8-byte block header has already
    /// been consumed) into a pooled buffer.
    async fn read_simple_packet(
        &mut self,
        header: &BlockHeader,
        byte_order: Endianness,
    ) -> Result<PooledNgPacket, PcapNgParseError> {
        let mut original = [0u8; 4];
        self.reader.read_exact(&mut original).await?;
        let original_length = byte_order.u32_from_bytes(original);
        let block_length = header.block_length_as_u32(byte_order);

        // SPB minimum_size = 16 = 8 (BlockHeader) + 4 (original_length) + 4 (footer).
        if (block_length as usize) < 16 {
            return Err(PcapNgParseError::MinimumSizeNotMet(
                16,
                block_length as usize,
            ));
        }
        // Captured payload is padded to 32 bits; recover it from the block length.
        let captured_padded = (block_length as usize) - 16;
        let content_len = captured_padded.min(original_length as usize);

        let (slot_index, mut buffer) = self.acquire().await?;
        // Everything after acquire must route errors through return_buffer.
        let result = async {
            read_into(
                &mut self.reader,
                &mut buffer,
                content_len,
                captured_padded - content_len,
            )
            .await?;
            // Footer (trailing block length).
            let mut footer = [0u8; 4];
            self.reader.read_exact(&mut footer).await?;
            Ok::<_, PcapNgParseError>(())
        }
        .await;

        match result {
            Ok(()) => {
                let any_header = AnyPacketHeader::PcapNgSimple {
                    block_length,
                    original_length,
                };
                Ok(self
                    .pool
                    .create_packet(any_header, content_len, slot_index, buffer))
            }
            Err(err) => {
                self.pool.return_buffer(slot_index, buffer);
                Err(err)
            }
        }
    }

    /// Acquires a buffer from the pool, mapping pool shutdown to an IO error.
    async fn acquire(&self) -> Result<(u32, Box<[u8]>), PcapNgParseError> {
        self.pool.acquire().await.ok_or_else(|| {
            PcapNgParseError::IO(std::io::Error::other("buffer pool has been shut down"))
        })
    }
}

/// Reads `content_len` bytes into `buffer` (growing it if needed), then consumes
/// and discards `skip` trailing bytes (block padding).
async fn read_into<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut Box<[u8]>,
    content_len: usize,
    skip: usize,
) -> Result<(), PcapNgParseError> {
    if buffer.len() < content_len {
        *buffer = vec![0u8; content_len].into_boxed_slice();
    }
    reader.read_exact(&mut buffer[..content_len]).await?;
    if skip > 0 {
        let mut pad = [0u8; 8];
        let mut remaining = skip;
        while remaining > 0 {
            let n = remaining.min(pad.len());
            reader.read_exact(&mut pad[..n]).await?;
            remaining -= n;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap_ng::AsyncPcapNgReader;
    use etherparse::SlicedPacket;

    const LE: &str = "test_data/ng/test001_le.pcapng";
    const BE: &str = "test_data/ng/test001_be.pcapng";

    async fn open(path: &str) -> AsyncPooledPcapNgReader<tokio::fs::File> {
        let file = tokio::fs::File::open(path).await.expect("open file");
        AsyncPooledPcapNgReader::new(
            file,
            NonZeroUsize::new(8).unwrap(),
            NonZeroU32::new(65536).unwrap(),
        )
        .await
        .expect("create reader")
    }

    #[tokio::test]
    async fn read_packets_from_file_le() {
        read_packets_from_file(LE).await;
    }

    #[tokio::test]
    async fn read_packets_from_file_be() {
        read_packets_from_file(BE).await;
    }

    async fn read_packets_from_file(path: &str) {
        let mut reader = open(path).await;
        let mut count = 0;
        while let Some(packet) = reader.next_packet().await.expect("next_packet") {
            let data = packet.data();
            // Should parse as an ethernet frame like the borrowed reader test.
            SlicedPacket::from_ethernet(data).expect("parse packet");
            assert!(packet.header().original_length() > 0);
            count += 1;
        }
        assert!(
            count > 0,
            "should have read at least one packet from {path}"
        );
    }

    #[tokio::test]
    async fn send_packets_through_channel() {
        let file = tokio::fs::File::open(LE).await.expect("open file");
        let mut reader = AsyncPooledPcapNgReader::new(
            file,
            NonZeroUsize::new(4).unwrap(),
            NonZeroU32::new(65536).unwrap(),
        )
        .await
        .expect("create reader");

        let (tx, mut rx) = tokio::sync::mpsc::channel::<PooledNgPacket>(16);
        let producer = tokio::spawn(async move {
            let mut sent = 0usize;
            while let Some(packet) = reader.next_packet().await.expect("next_packet") {
                if tx.send(packet).await.is_err() {
                    break;
                }
                sent += 1;
            }
            sent
        });

        let mut received = 0usize;
        while let Some(packet) = rx.recv().await {
            assert!(!packet.data().is_empty());
            received += 1;
        }

        let sent = producer.await.expect("producer task");
        assert_eq!(sent, received);
        assert!(received > 0);
    }

    #[tokio::test]
    async fn recycle_batch() {
        let mut reader = open(LE).await;
        let mut batch = Vec::new();
        while let Some(packet) = reader.next_packet().await.expect("next_packet") {
            batch.push(packet);
        }
        assert!(!batch.is_empty());
        // Returning the whole batch must not corrupt the pool.
        reader.pool().recycle(batch);
        assert!(reader.pool().try_acquire().is_some());
    }

    #[tokio::test]
    async fn oversized_buffer_grows() {
        // A tiny nominal buffer forces the grow-on-demand path; every packet
        // must still be read correctly and match a normally-sized reader.
        let file_small = tokio::fs::File::open(LE).await.expect("open file");
        let mut small = AsyncPooledPcapNgReader::new(
            file_small,
            NonZeroUsize::new(2).unwrap(),
            NonZeroU32::new(4).unwrap(),
        )
        .await
        .expect("create reader");

        let mut oracle = open(LE).await;
        loop {
            let a = small.next_packet().await.expect("small next_packet");
            let b = oracle.next_packet().await.expect("oracle next_packet");
            match (a, b) {
                (Some(a), Some(b)) => {
                    assert_eq!(a.data(), b.data(), "grown-buffer data must match");
                    assert_eq!(a.header(), b.header());
                }
                (None, None) => break,
                _ => panic!("packet count mismatch between small and normal reader"),
            }
        }
    }

    #[tokio::test]
    async fn oracle_vs_borrowed() {
        // The pooled reader must yield the same headers and bytes as the
        // borrowed AsyncPcapNgReader on the same file.
        let mut pooled = open(LE).await;
        let borrowed_file = tokio::fs::File::open(LE).await.expect("open file");
        let mut borrowed = AsyncPcapNgReader::new(borrowed_file)
            .await
            .expect("borrowed reader");

        loop {
            let p = pooled.next_packet().await.expect("pooled next_packet");
            let b = borrowed.next_packet().await.expect("borrowed next_packet");
            match (p, b) {
                (Some(p), Some((header, data))) => {
                    assert_eq!(p.header(), &header, "headers must match");
                    assert_eq!(p.data(), data, "data must match byte-for-byte");
                }
                (None, None) => break,
                _ => panic!("packet count mismatch"),
            }
        }
    }
}
