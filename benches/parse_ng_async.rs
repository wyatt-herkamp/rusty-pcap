#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
//! Async pcap-ng benchmarks, focused on the pooled reader pipelines:
//! borrowed baseline vs pooled, pool-size sweeps, channel roundtrip,
//! batch `recycle` vs per-packet drop, grow-on-demand buffer sizing, and
//! multi-consumer fan-out.
use std::num::{NonZeroU32, NonZeroUsize};

use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use rusty_pcap::pcap_ng::{AsyncPcapNgReader, AsyncPooledPcapNgReader, PooledNgPacket};
use tokio::{fs::File, io::BufReader};

const NG_FILE: &str = "test_data/test.pcapng";

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
}

/// Baseline: the borrowed reader, whose `next_packet` hands back a slice into an
/// internal scratch buffer (no per-packet ownership).
fn ng_async_borrowed(c: &mut Criterion) {
    c.bench_function("ng_async_borrowed", |b| {
        b.to_async(rt()).iter(|| async {
            let file = BufReader::new(File::open(NG_FILE).await.unwrap());
            let mut reader = AsyncPcapNgReader::new(file).await.unwrap();
            while let Ok(Some((_header, data))) = reader.next_packet().await {
                std::hint::black_box(data);
            }
        })
    });
}

/// Pooled reader draining straight through, swept over pool size. Compare
/// against `ng_async_borrowed` to see the cost of owned pooled buffers.
fn ng_pooled_reader(c: &mut Criterion) {
    let mut group = c.benchmark_group("ng_pooled_reader");
    for pool_size in [4, 8, 16, 32] {
        group.bench_with_input(
            BenchmarkId::new("pool_size", pool_size),
            &pool_size,
            |b, &pool_size| {
                b.to_async(rt()).iter(|| async move {
                    let file = BufReader::new(File::open(NG_FILE).await.unwrap());
                    let mut reader = AsyncPooledPcapNgReader::with_default_buffer_size(
                        file,
                        NonZeroUsize::new(pool_size).unwrap(),
                    )
                    .await
                    .unwrap();
                    while let Ok(Some(packet)) = reader.next_packet().await {
                        std::hint::black_box(packet.data());
                    }
                })
            },
        );
    }
    group.finish();
}

/// Producer/consumer over an mpsc channel: exercises sending owned packets
/// across tasks and returning buffers to the pool from a different task on drop.
fn ng_pooled_channel_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("ng_pooled_channel_roundtrip");
    for pool_size in [4, 8, 16, 32] {
        group.bench_with_input(
            BenchmarkId::new("pool_size", pool_size),
            &pool_size,
            |b, &pool_size| {
                b.to_async(rt()).iter(|| async move {
                    let file = BufReader::new(File::open(NG_FILE).await.unwrap());
                    let mut reader = AsyncPooledPcapNgReader::with_default_buffer_size(
                        file,
                        NonZeroUsize::new(pool_size).unwrap(),
                    )
                    .await
                    .unwrap();
                    let (tx, mut rx) = tokio::sync::mpsc::channel::<PooledNgPacket>(pool_size);
                    let producer = tokio::spawn(async move {
                        while let Ok(Some(packet)) = reader.next_packet().await {
                            if tx.send(packet).await.is_err() {
                                break;
                            }
                        }
                    });
                    while let Some(packet) = rx.recv().await {
                        std::hint::black_box(packet.data());
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
    let file = BufReader::new(File::open(NG_FILE).await.unwrap());
    let mut reader =
        AsyncPooledPcapNgReader::with_default_buffer_size(file, NonZeroUsize::new(POOL).unwrap())
            .await
            .unwrap();
    let pool = reader.pool().clone();
    // Keep in-flight (channel + batch) below POOL so the producer never starves.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<PooledNgPacket>(chunk);
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

fn ng_pooled_recycle_vs_drop(c: &mut Criterion) {
    const CHUNK: usize = 16;
    let mut group = c.benchmark_group("ng_pooled_recycle_vs_drop");
    group.bench_function("batch_recycle", |b| {
        b.to_async(rt()).iter(|| recycle_run(CHUNK, true))
    });
    group.bench_function("individual_drop", |b| {
        b.to_async(rt()).iter(|| recycle_run(CHUNK, false))
    });
    group.finish();
}

/// Grow-on-demand cost: sweep the nominal pool buffer size. A small nominal
/// size forces the reader to reallocate slots to fit larger captured packets
/// (pcap-ng has no global snap length); a large one pre-fits everything.
fn ng_pooled_buffer_size(c: &mut Criterion) {
    let mut group = c.benchmark_group("ng_pooled_buffer_size");
    for buffer_size in [64u32, 1500, 65536] {
        group.bench_with_input(
            BenchmarkId::new("buffer_size", buffer_size),
            &buffer_size,
            |b, &buffer_size| {
                b.to_async(rt()).iter(|| async move {
                    let file = BufReader::new(File::open(NG_FILE).await.unwrap());
                    let mut reader = AsyncPooledPcapNgReader::new(
                        file,
                        NonZeroUsize::new(16).unwrap(),
                        NonZeroU32::new(buffer_size).unwrap(),
                    )
                    .await
                    .unwrap();
                    while let Ok(Some(packet)) = reader.next_packet().await {
                        std::hint::black_box(packet.data());
                    }
                })
            },
        );
    }
    group.finish();
}

/// Fan-out: one producer, N consumers over a flume MPMC channel. Stresses
/// concurrent buffer returns to the pool from multiple threads.
fn ng_pooled_fanout(c: &mut Criterion) {
    const POOL: usize = 32;
    let mut group = c.benchmark_group("ng_pooled_fanout");
    for consumers in [1usize, 2, 4] {
        group.bench_with_input(
            BenchmarkId::new("consumers", consumers),
            &consumers,
            |b, &consumers| {
                b.to_async(rt()).iter(|| async move {
                    let file = BufReader::new(File::open(NG_FILE).await.unwrap());
                    let mut reader = AsyncPooledPcapNgReader::with_default_buffer_size(
                        file,
                        NonZeroUsize::new(POOL).unwrap(),
                    )
                    .await
                    .unwrap();
                    let (tx, rx) = flume::bounded::<PooledNgPacket>(POOL);
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
    name = ng_async_benches;
    config = Criterion::default().sample_size(30);
    targets =
        ng_async_borrowed,
        ng_pooled_reader,
        ng_pooled_channel_roundtrip,
        ng_pooled_recycle_vs_drop,
        ng_pooled_buffer_size,
        ng_pooled_fanout,
);
criterion_main!(ng_async_benches);
