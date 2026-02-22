#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
use std::{hint::black_box, time::SystemTime};

use criterion::{Criterion, criterion_group, criterion_main};
use rusty_pcap::{
    byte_order::Endianness,
    pcap::packet_header::{PacketHeader, PacketTimestamp},
};

fn parse_packet_header_little_endian(c: &mut Criterion) {
    let header = {
        let packet_header = PacketHeader {
            timestamp: PacketTimestamp::try_from(SystemTime::now()).unwrap(),
            orig_len: 100,
            include_len: 100,
        };
        let mut buf = Vec::new();
        packet_header
            .write(
                &mut buf,
                Endianness::LittleEndian,
                &rusty_pcap::Version::PCAP_VERSION_2_4,
            )
            .unwrap();
        buf
    };
    let header: [u8; 16] = header.try_into().unwrap();
    c.bench_function("parse_packet_header_little_endian", |b| {
        b.iter(|| {
            let _parsed_header = PacketHeader::parse_bytes(
                black_box(&header),
                black_box(Endianness::LittleEndian),
                black_box(&rusty_pcap::Version::PCAP_VERSION_2_4),
            )
            .unwrap();
        })
    });
}

fn parse_packet_header_big_endian(c: &mut Criterion) {
    let header = {
        let packet_header = PacketHeader {
            timestamp: PacketTimestamp::try_from(SystemTime::now()).unwrap(),
            orig_len: 100,
            include_len: 100,
        };
        let mut buf = Vec::new();
        packet_header
            .write(
                &mut buf,
                Endianness::BigEndian,
                &rusty_pcap::Version::PCAP_VERSION_2_4,
            )
            .unwrap();
        buf
    };
    let header: [u8; 16] = header.try_into().unwrap();
    c.bench_function("parse_packet_header_big_endian", |b| {
        b.iter(|| {
            let _parsed_header = PacketHeader::parse_bytes(
                black_box(&header),
                black_box(Endianness::BigEndian),
                black_box(&rusty_pcap::Version::PCAP_VERSION_2_4),
            )
            .unwrap();
        })
    });
}
criterion_group!(
    benches,
    parse_packet_header_little_endian,
    parse_packet_header_big_endian
);
criterion_main!(benches);
