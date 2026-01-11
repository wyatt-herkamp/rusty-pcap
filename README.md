# Rusty-Pcap [![Latest Version]][crates.io]
[Latest Version]: https://img.shields.io/crates/v/rusty-pcap.svg
[crates.io]: https://crates.io/crates/rusty-pcap

An asynchronous and synchronous PCAP file reader for Rust



## Pcap Support

This library provides support for reading traditional PCAP files, including both little-endian and big-endian formats. It can read packet headers and data efficiently, allowing for easy integration into network analysis tools.

Synchronous writing support is also provided.

## Pcap-NG Support

This library includes support for reading PCAP-NG files, however, not all block types are supported yet. Currently supported blocks include:

- [x] Section Header Block
- [x] Interface Description Block
- [x] Enhanced Packet Block
- [x] Simple Packet Block
- [x] Name Resolution Block

No support for writing PCAP-NG files is currently available.

## Async Support

Async support is provided using the `tokio-async` feature flag. This allows for non-blocking reading of PCAP and PCAP-NG files, making it suitable for high-performance applications.

This is limited to Tokio's async runtime.

### Non Tokio Async Support

At this time, only Tokio's async runtime is supported. If there is enough demand for other async runtimes (such as async-std), support may be added in the future. Please open an issue if you would like to see this feature.


## Reading Both PCAP and PCAP-NG Files

The `AnyPcapReader` struct allows for reading both PCAP and PCAP-NG files seamlessly. It automatically detects the file format and provides a unified interface for reading packets.
An asynchronous version, `AsyncAnyPcapReader`, is also available when the `tokio-async` feature is enabled.

## Benefits over `pcap` crate

- Pure Rust implementation with no need for native libraries
- Support for Rust's async ecosystem with Tokio
- Reading is done over the Read trait, allowing for directly reading from any source implementing Read (e.g., files, network streams, in-memory buffers) without needing to use unix pipes.


## Disadvantages over `pcap` crate

- Does not support live packet capturing
- May not fully support older or outdated pcap file formats or versions

## License

This project is licensed under the MIT License And Apache License 2.0 - see the [LICENSE](LICENSE) file for details.