#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
// Generate test with criterion
use criterion::{Criterion, criterion_group, criterion_main};
use rusty_pcap::pcap_ng::blocks::Block;
use std::hint::black_box;

fn parse_enhanced_packets(c: &mut Criterion) {
    let block_content = {
        let packet_content = vec![1; 2048];
        let packet = rusty_pcap::pcap_ng::blocks::EnhancedPacket {
            block_length: 0,
            interface_id: 1,
            timestamp_high: 5000,
            timestamp_low: 6000,
            captured_length: packet_content.len() as u32,
            original_length: packet_content.len() as u32,
            content: &packet_content,
            options: None,
        };
        let mut buffer = Vec::new();
        packet
            .write(&mut buffer, rusty_pcap::byte_order::LittleEndian)
            .unwrap();
        buffer
    };
    let mut content_buffer = vec![0; 2048];
    c.bench_function("parse_enhanced_packets", |b| {
        b.iter(|| {
            let mut reader = std::io::Cursor::new(&block_content);
            let header = rusty_pcap::pcap_ng::blocks::BlockHeader::read(&mut reader).unwrap();
            let _packet = rusty_pcap::pcap_ng::blocks::EnhancedPacket::read_with_header(
                &mut reader,
                &header,
                Some(rusty_pcap::byte_order::Endianness::LittleEndian),
                &mut content_buffer,
            )
            .unwrap();
            black_box(_packet);
        })
    });
}

criterion_group!(
    name = ng_blocks;
    config = Criterion::default().sample_size(500);
    targets = parse_enhanced_packets
);
criterion_main!(ng_blocks);
