//! Asynchronous PCAP io
//!
//! Requires the `tokio-async` feature
mod reader;
pub use reader::AsyncPcapReader;

mod pooled_reader;
pub use pooled_reader::AsyncPooledPcapReader;
