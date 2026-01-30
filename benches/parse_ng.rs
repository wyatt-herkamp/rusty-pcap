#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
// Generate test with criterion
use criterion::{Criterion, criterion_group, criterion_main};
use rusty_pcap::pcap_ng::SyncPcapNgReader;
use std::{fs::File, hint::black_box, io::BufReader};

fn parse_ng_with_rusty_pcap(c: &mut Criterion) {
    c.bench_function("parse_ng_with_rusty_pcap", |b| {
        b.iter(|| {
            let file =
                File::open("/media/Other/polygon-io/utp.trades.2023.04.12.truncated.pcap").unwrap();
            let packets = SyncPcapNgReader::new(BufReader::new(file));
            let mut packets = packets.unwrap();
            while let Ok(Some(block)) = black_box(packets.next_block()) {
                let _ = black_box(block);
            }
        })
    });
}
fn parse_ng_with_rusty_pcap_no_buf(c: &mut Criterion) {
    c.bench_function("parse_ng_with_rusty_pcap_no_buf", |b| {
        b.iter(|| {
            let file = File::open("test_data/test.pcapng").unwrap();
            let packets = SyncPcapNgReader::new(file);
            let mut packets = packets.unwrap();
            while let Ok(Some(block)) = black_box(packets.next_block()) {
                let _ = black_box(block);
            }
        })
    });
}
fn parse_ng_with_rusty_pcap_no_io(c: &mut Criterion) {
    let content = std::fs::read("test_data/test.pcapng").expect("Failed to read test.pcap");
    c.bench_function("parse_ng_with_rusty_pcap_no_io", |b| {
        b.iter(|| {
            let cursor = std::io::Cursor::new(&content);
            let packets = SyncPcapNgReader::new(cursor);
            let mut packets = packets.unwrap();
            while let Ok(Some(block)) = black_box(packets.next_block()) {
                let _ = black_box(block);
            }
        })
    });
}
fn parse_ng_with_libpcap(c: &mut Criterion) {
    c.bench_function("parse_ng_with_libpcap", |b| {
        b.iter(|| {
            let packets = pcap::Capture::from_file(
                "/media/Other/polygon-io/utp.trades.2023.04.12.truncated.pcap",
            );
            let mut packets = packets.unwrap();
            while let Ok(packet) = black_box(packets.next_packet()) {
                let _ = black_box(packet);
            }
        })
    });
}
criterion_group!(
    name = ng_benches;
    config = Criterion::default().sample_size(20);

    targets =parse_ng_with_rusty_pcap, parse_ng_with_libpcap,    parse_ng_with_rusty_pcap_no_buf,
    parse_ng_with_rusty_pcap_no_io,
);
criterion_main!(ng_benches);
