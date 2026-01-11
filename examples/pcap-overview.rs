use std::{fs::File, io::BufReader, path::PathBuf};

use clap::Parser;
use rusty_pcap::any_reader::SyncAnyPcapReader;

#[derive(Parser, Debug)]
#[clap(name = "pcap-overview")]
struct PcapOverview {
    // Path to the pcapng file to read
    file: PathBuf,
}
fn main() -> anyhow::Result<()> {
    let cli = PcapOverview::parse();
    let file = File::open(cli.file)?;
    let packet_reader = SyncAnyPcapReader::new(BufReader::new(file))?;

    let mut packet_count = 0;
    let mut packet_reader = packet_reader;
    while let Some(_packet) = packet_reader.next_packet()? {
        packet_count += 1;
    }
    println!("-- PCAP File Overview --");
    println!("Total packets in pcap file: {}", packet_count);
    println!(
        "Pcap file version: {}.{}",
        packet_reader.version().major,
        packet_reader.version().minor
    );
    println!("Pcap file type: {}", packet_reader.file_type());
    println!("-- End of Overview --");
    Ok(())
}
