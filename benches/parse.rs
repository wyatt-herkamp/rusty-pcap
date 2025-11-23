// Generate test with criterion

use criterion::{Criterion, criterion_group, criterion_main};
use rusty_pcap::pcap::sync::SyncPcapReader;
use std::{fs::File, hint::black_box, io::BufReader};

fn parse_with_rusty_pcap(c: &mut Criterion) {
    c.bench_function("parse_with_rusty_pcap", |b| {
        b.iter(|| {
            let file = File::open("test_data/test.pcap").expect("Failed to open test.pcap");
            let packets = SyncPcapReader::new(BufReader::new(file));
            let mut packets = packets.unwrap();
            while let Ok(Some((_header, _data))) = black_box(packets.next_packet()) {
                let _ = black_box((_header, _data));
            }
        })
    });
}
fn parse_with_rusty_pcap_no_io(c: &mut Criterion) {
    let content = std::fs::read("test_data/test.pcap").expect("Failed to read test.pcap");
    c.bench_function("parse_with_rusty_pcap_no_io", |b| {
        b.iter(|| {
            let cursor = std::io::Cursor::new(&content);
            let packets = SyncPcapReader::new(cursor);
            let mut packets = packets.unwrap();
            while let Ok(Some((_header, _data))) = black_box(packets.next_packet()) {
                let _ = black_box((_header, _data));
            }
        })
    });
}
fn parse_with_libpcap(c: &mut Criterion) {
    c.bench_function("parse_with_libpcap", |b| {
        b.iter(|| {
            let packets = pcap::Capture::from_file("test_data/test.pcap");
            let mut packets = packets.unwrap();
            while let Ok(packet) = black_box(packets.next_packet()) {
                let _ = black_box(packet);
            }
        })
    });
}
criterion_group!(
    benches,
    parse_with_rusty_pcap,
    parse_with_rusty_pcap_no_io,
    parse_with_libpcap
);
criterion_main!(benches);
