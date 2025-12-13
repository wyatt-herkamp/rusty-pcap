# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
