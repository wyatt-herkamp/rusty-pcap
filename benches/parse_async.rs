#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
use std::num::NonZeroUsize;

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rusty_pcap::pcap::{AsyncPcapReader, AsyncPooledPcapReader, PooledPacket};
use tokio::{fs::File, io::BufReader};

const PCAP_FILE: &str = "test_data/test.pcap";

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

/// Batch `recycle` (single atomic splice + one wakeup) vs per-packet drop
/// (one CAS + wakeup each) when returning buffers from a consumer task.
async fn recycle_run(chunk: usize, use_recycle: bool) {
    const POOL: usize = 64;
    let file = File::open(PCAP_FILE).await.unwrap();
    let mut reader = AsyncPooledPcapReader::new(file, NonZeroUsize::new(POOL).unwrap())
        .await
        .unwrap();
    let pool = reader.pool().clone();
    // Keep in-flight (channel + batch) below POOL so the producer never starves.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<PooledPacket>(chunk);
    let producer = tokio::spawn(async move {
        while let Ok(Some(packet)) = reader.next_packet().await {
            if tx.send(packet).await.is_err() {
                break;
            }
        }
    });
    let mut batch = Vec::with_capacity(chunk);
    while let Some(packet) = rx.recv().await {
        batch.push(packet);
        if batch.len() == chunk {
            if use_recycle {
                pool.recycle(batch.drain(..));
            } else {
                batch.clear();
            }
        }
    }
    if use_recycle {
        pool.recycle(batch.drain(..));
    } else {
        batch.clear();
    }
    producer.await.unwrap();
}

fn parse_pooled_recycle_vs_drop(c: &mut Criterion) {
    const CHUNK: usize = 16;
    let mut group = c.benchmark_group("pooled_recycle_vs_drop");
    group.bench_function("batch_recycle", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| recycle_run(CHUNK, true))
    });
    group.bench_function("individual_drop", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| recycle_run(CHUNK, false))
    });
    group.finish();
}

/// Fan-out: one producer, N consumers over a flume MPMC channel. Stresses
/// concurrent buffer returns to the pool from multiple threads.
fn parse_pooled_fanout(c: &mut Criterion) {
    const POOL: usize = 32;
    let mut group = c.benchmark_group("pooled_fanout");
    for consumers in [1usize, 2, 4] {
        group.bench_with_input(
            BenchmarkId::new("consumers", consumers),
            &consumers,
            |b, &consumers| {
                b.to_async(tokio::runtime::Runtime::new().unwrap())
                    .iter(|| async move {
                        let file = File::open(PCAP_FILE).await.unwrap();
                        let mut reader =
                            AsyncPooledPcapReader::new(file, NonZeroUsize::new(POOL).unwrap())
                                .await
                                .unwrap();
                        let (tx, rx) = flume::bounded::<PooledPacket>(POOL);
                        let producer = tokio::spawn(async move {
                            while let Ok(Some(packet)) = reader.next_packet().await {
                                if tx.send_async(packet).await.is_err() {
                                    break;
                                }
                            }
                        });
                        let mut handles = Vec::with_capacity(consumers);
                        for _ in 0..consumers {
                            let rx = rx.clone();
                            handles.push(tokio::spawn(async move {
                                while let Ok(packet) = rx.recv_async().await {
                                    std::hint::black_box(packet.data());
                                }
                            }));
                        }
                        drop(rx);
                        producer.await.unwrap();
                        for handle in handles {
                            handle.await.unwrap();
                        }
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
    parse_pooled_recycle_vs_drop,
    parse_pooled_fanout,
);
criterion_main!(benches);
