use std::{fs::File, io::BufReader, path::PathBuf};

use clap::Parser;
use rusty_pcap::pcap::sync::SyncPcapReader;

#[derive(Parser, Debug)]
#[clap(name = "count-packets-in-pcap")]
struct CountPacketsInPcap {
    // Path to the pcapng file to read
    file: PathBuf,
}
fn main() -> anyhow::Result<()> {
    let cli = CountPacketsInPcap::parse();
    let file = File::open(cli.file)?;
    let packet_reader = SyncPcapReader::new(BufReader::new(file))?;

    let mut packet_count = 0;
    let mut packet_reader = packet_reader;
    while let Some(_packet) = packet_reader.next_packet()? {
        packet_count += 1;
    }
    println!("Total packets in pcap file: {}", packet_count);

    Ok(())
}
