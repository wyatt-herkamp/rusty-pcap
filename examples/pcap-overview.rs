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
    let mut average_number_of_bytes: usize = 0;
    let mut highest_packet_size: usize = 0;
    let mut lowest_packet_size: usize = 0;
    let mut packet_reader = packet_reader;
    while let Some((_header, data)) = packet_reader.next_packet()? {
        packet_count += 1;
        let packet_size = data.len();
        average_number_of_bytes += packet_size;
        if packet_size > highest_packet_size {
            highest_packet_size = packet_size;
        }
        if lowest_packet_size == 0 || packet_size < lowest_packet_size {
            lowest_packet_size = packet_size;
        }
    }
    if packet_count > 0 {
        average_number_of_bytes /= packet_count;
    }
    println!("-- PCAP File Overview --");
    println!("Total packets in pcap file: {}", packet_count);
    println!(
        "Pcap file version: {}.{}",
        packet_reader.version().major,
        packet_reader.version().minor
    );
    println!("Pcap file type: {}", packet_reader.file_type());
    println!("Average packet size: {} bytes", average_number_of_bytes);
    println!("Highest packet size: {} bytes", highest_packet_size);
    println!("Lowest packet size: {} bytes", lowest_packet_size);
    println!("-- End of Overview --");
    Ok(())
}
