#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rusty_pcap::pcap::AsyncPcapReader;
use tokio::{fs::File, io::BufReader};

fn parse_with_tokio_async(c: &mut Criterion) {
    c.bench_with_input(
        BenchmarkId::new("parse_with_tokio_async", 1024),
        &1024,
        |b, &_s| {
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| async {
                    let file = BufReader::new(File::open("test_data/test.pcap").await.unwrap());
                    let mut packets = AsyncPcapReader::with_buf_reader(file).await.unwrap();
                    while let Ok(Some((_header, _data))) = packets.next_packet().await {
                        let _ = (_header, _data);
                    }
                })
        },
    );
}
fn parse_with_tokio_async_internal_buffer_size(c: &mut Criterion) {
    c.bench_with_input(
        BenchmarkId::new("parse_with_defined_buffer", 1024),
        &1024,
        |b, &_s| {
            b.to_async(tokio::runtime::Runtime::new().unwrap())
                .iter(|| async {
                    let file = File::open("test_data/test.pcap").await.unwrap();
                    let mut packets = AsyncPcapReader::new(file).await.unwrap();
                    while let Ok(Some((_header, _data))) = packets.next_packet().await {
                        let _ = (_header, _data);
                    }
                })
        },
    );
}

criterion_group!(
    benches,
    parse_with_tokio_async,
    parse_with_tokio_async_internal_buffer_size,
);
criterion_main!(benches);
