//! Asynchronous PCAP io
//!
//! Requires the `tokio-async` feature
mod reader;
pub use reader::AsyncPcapNgReader;

mod pooled_reader;
pub use pooled_reader::{AsyncPooledPcapNgReader, DEFAULT_BUFFER_SIZE, PooledNgPacket};

// Re-exported for discoverability: the pooled pcap-ng reader shares the same
// lock-free buffer pool as the pcap one.
pub use crate::buffer_pool::{BufferPool, PooledPacket};
