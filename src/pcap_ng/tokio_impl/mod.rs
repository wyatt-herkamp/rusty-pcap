//! Asynchronous PCAP io
//!
//! Requires the `tokio-async` feature
mod reader;
pub use reader::AsyncPcapNgReader;
