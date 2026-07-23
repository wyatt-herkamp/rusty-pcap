# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [0.8.0] (UNRELEASED)
- Add PCAPNG Pooled Reader (`AsyncPooledPcapNgReader`)
  - Oversized captured packets grow their pooled buffer on demand instead of erroring (pcap-ng has no global snap length)
- `PooledPacket` is now generic over its header type (`PooledPacket<H = PacketHeader>`); pcap-ng packets are `PooledNgPacket = PooledPacket<AnyPacketHeader>`
- Moved the buffer pool to the shared top-level `buffer_pool` module (used by both pcap and pcap-ng); still re-exported from `pcap` for backward compatibility
- Added async pcap-ng benchmarks and pooled recycle-vs-drop / fan-out benchmarks


## [0.7.1] (2026-07-22)
- Improved buffer pool performance

## [0.7.0] (2025-05-16)
- Improved documentation throughout the codebase
- Updates all dependencies to their latest versions
- Adds testing against the pcapng-test-generator
- Fixed Options parsing in pcapng files
- Implement InterfaceStatisticsBlock, CustomBlock, and DecryptionSecretsBlock parsing in pcapng files

## [0.6.0] (2026-05-02)
- Encourage Proper Size Buffer Usage inside async pcap reader
  - `AsyncPcapReader::new` will now create a BufReader and return `AsyncPcapReader<BufReader<R>>`
  - `AsyncPcapReader::with_buf_reader` uses a predefined BufReader and returns `AsyncPcapReader<BufReader<R>>`
  - `AsyncPcapReader::new_without_buffer` is used when no buffer is desired and returns `AsyncPcapReader<R>`
- Added Async Benchmarking
- Added a pooled async pcap reader

## [0.5.0] (2026-01-30)
- Added AnyPcapReader to read both pcap and pcapng files
- Introduce AsyncPcapNgReader for asynchronous pcapng reading
- Added AsyncAnyPcapReader for asynchronous reading of both pcap and pcapng files
- Cargo Check Fix

## [0.4.0] (2026-01-06)
- Fixed Bad Error Name

## [0.3.0] (2025-12-13)
- Added `documentation` field to `Cargo.toml`
- Added libpcap version 2.2 support
- Introduce PacketTimestamp struct for better timestamp handling
- Add pcap writer support

## [0.2.0] (2025-11-23)
- Cleanup code by using a ByteOrder trait
- Removed unwrap calls
- Introduce Benchmarking for parsing performance
- Initial PcapNG support

## [0.1.0] (2025-11-22)

Initial release.


[0.1.0]:https://github.com/wyatt-herkamp/rusty-pcap/releases/tag/0.1.0
[0.2.0]:https://github.com/wyatt-herkamp/rusty-pcap/releases/tag/0.2.0
[0.3.0]:https://github.com/wyatt-herkamp/rusty-pcap/releases/tag/0.3.0
[0.4.0]:https://github.com/wyatt-herkamp/rusty-pcap/releases/tag/0.4.0
[0.5.0]:https://github.com/wyatt-herkamp/rusty-pcap/releases/tag/0.5.0
[0.6.0]:https://github.com/wyatt-herkamp/rusty-pcap/releases/tag/0.6.0
[0.7.0]:https://github.com/wyatt-herkamp/rusty-pcap/releases/tag/0.7.0