#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]
use clap::Parser;
use rusty_pcap::pcap::{AsyncPooledPcapReader, PooledPacket};
use std::{num::NonZeroUsize, path::PathBuf};
use tokio::{fs::File, io::BufReader};

#[derive(Parser, Debug)]
#[clap(
    name = "pooled-pcap-overview",
    about = "Provides an overview of a pcap file using pooled reading. Only PCAP is supported."
)]
struct PcapOverview {
    // Path to the pcapng file to read
    file: PathBuf,
    #[clap(long, help = "Enable Tokio console subscriber for async tracing", action = clap::ArgAction::SetTrue)]
    tokio_subscriber: bool,
}
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = PcapOverview::parse();
    if cli.tokio_subscriber {
        console_subscriber::init();
    }

    let file = File::open(cli.file).await?;
    let packet_reader = AsyncPooledPcapReader::new(file, NonZeroUsize::new(2).unwrap()).await?;

    let (tx, rx) = flume::bounded(100);

    let send_task = tokio::spawn(sender(tx, packet_reader));
    let rx_1 = tokio::spawn(receiver(rx.clone(), 1));
    let rx_2 = tokio::spawn(receiver(rx, 2));

    send_task.await??;
    rx_1.await?;
    rx_2.await?;

    Ok(())
}

async fn sender(
    tx: flume::Sender<PooledPacket>,
    mut packet_reader: AsyncPooledPcapReader<BufReader<File>>,
) -> anyhow::Result<()> {
    while let Some(packet) = packet_reader.next_packet().await? {
        println!(
            "Sending packet with header: {:?}, data length: {}",
            packet.header(),
            packet.data().len()
        );
        tx.send_async(packet).await?;
    }
    Ok(())
}

async fn receiver(rx: flume::Receiver<PooledPacket>, consumer: usize) {
    while let Ok(packet) = rx.recv_async().await {
        println!(
            "Consumer: {consumer} Received packet with header: {:?}, data length: {}",
            packet.header(),
            packet.data().len()
        );
        // Simulate processing time
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
