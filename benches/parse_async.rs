#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
use std::num::NonZeroUsize;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rusty_pcap::pcap::{AsyncPcapReader, AsyncPooledPcapReader};
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

fn parse_with_pooled_reader(c: &mut Criterion) {
    let mut group = c.benchmark_group("pooled_reader");
    for pool_size in [4, 8, 16, 32] {
        group.bench_with_input(
            BenchmarkId::new("pool_size", pool_size),
            &pool_size,
            |b, &pool_size| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| async move {
                        let file = File::open("test_data/test.pcap").await.unwrap();
                        let mut packets =
                            AsyncPooledPcapReader::new(file, NonZeroUsize::new(pool_size).unwrap())
                                .await
                                .unwrap();
                        while let Ok(Some(packet)) = packets.next_packet().await {
                            let _ = packet.data();
                        }
                    })
            },
        );
    }
    group.finish();
}

fn parse_pooled_with_buf_reader(c: &mut Criterion) {
    let mut group = c.benchmark_group("pooled_reader_buf");
    for pool_size in [4, 8, 16, 32] {
        group.bench_with_input(
            BenchmarkId::new("pool_size", pool_size),
            &pool_size,
            |b, &pool_size| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| async move {
                        let file = BufReader::new(File::open("test_data/test.pcap").await.unwrap());
                        let mut packets = AsyncPooledPcapReader::with_buf_reader(
                            file,
                            NonZeroUsize::new(pool_size).unwrap(),
                        )
                        .await
                        .unwrap();
                        while let Ok(Some(packet)) = packets.next_packet().await {
                            let _ = packet.data();
                        }
                    })
            },
        );
    }
    group.finish();
}

fn parse_pooled_channel_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("pooled_channel_roundtrip");
    for pool_size in [4, 8, 16, 32] {
        group.bench_with_input(
            BenchmarkId::new("pool_size", pool_size),
            &pool_size,
            |b, &pool_size| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| async move {
                        let file = File::open("test_data/test.pcap").await.unwrap();
                        let mut packets =
                            AsyncPooledPcapReader::new(file, NonZeroUsize::new(pool_size).unwrap())
                                .await
                                .unwrap();
                        let (tx, mut rx) = tokio::sync::mpsc::channel(pool_size);

                        let producer = tokio::spawn(async move {
                            while let Ok(Some(packet)) = packets.next_packet().await {
                                if tx.send(packet).await.is_err() {
                                    break;
                                }
                            }
                        });

                        while let Some(packet) = rx.recv().await {
                            let _ = packet.data();
                        }

                        producer.await.unwrap();
                    })
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    parse_with_tokio_async,
    parse_with_tokio_async_internal_buffer_size,
    parse_with_pooled_reader,
    parse_pooled_with_buf_reader,
    parse_pooled_channel_roundtrip,
);
criterion_main!(benches);
