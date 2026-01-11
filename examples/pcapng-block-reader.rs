use std::path::PathBuf;

use clap::Parser;
use rusty_pcap::pcap_ng::{
    SyncPcapNgReader,
    blocks::{PcapNgBlock, SectionHeaderBlock},
};
#[derive(Parser, Debug)]
#[clap(name = "pcapng-block-reader")]
struct BlockReaderCLI {
    #[clap(
        long,
        default_value = "false",
        action = clap::ArgAction::SetTrue,
        help = "If set, will fail on generic blocks. This is useful for debugging."
    )]
    fail_on_generic: bool,

    // Path to the pcapng file to read
    file: PathBuf,
}
fn main() -> anyhow::Result<()> {
    let cli = BlockReaderCLI::parse();
    let file = std::fs::File::open(cli.file)?;
    let mut reader = std::io::BufReader::new(file);
    let mut pcapng_reader = SyncPcapNgReader::new(&mut reader)?;
    debug_section_header(pcapng_reader.current_section());
    while let Some(block) = pcapng_reader.next_block()? {
        if cli.fail_on_generic && matches!(block, PcapNgBlock::Generic(_)) {
            return Err(anyhow::anyhow!(
                "Encountered a generic block, which is not expected."
            ));
        }
        debug_print_block(&block);
    }
    Ok(())
}
fn debug_print_block(block: &PcapNgBlock) {
    match block {
        PcapNgBlock::SectionHeader(header) => {
            debug_section_header(header);
        }
        PcapNgBlock::InterfaceDescription(interface) => {
            println!("--- Interface Description Block ---");
            println!("Block Length: {}", interface.block_length);
            println!("Link Type: {:?}", interface.link_type);
            println!("Snap Length: {}", interface.snap_length);
            if let Some(options) = &interface.options {
                println!("Options: {:?}", options);
            } else {
                println!("No options");
            }
            println!("--- End of Interface Description Block ---");
        }
        PcapNgBlock::SimplePacket(packet) => {
            println!("--- Simple Packet Block ---");
            println!("Block Length: {}", packet.block_length);
            println!("Data Length: {}", packet.original_length);
            println!("--- End of Simple Packet Block ---");
        }
        PcapNgBlock::Generic(generic) => {
            println!("--- Generic Block ---");
            println!("Block ID: {}", generic.block_id);
            println!("Block Length: {}", generic.block_length);
            println!("--- End of Generic Block ---");
        }
        PcapNgBlock::EnhancedPacket(enhanced) => {
            println!("--- Enchanced Packet ---");
            println!("Block Length: {}", enhanced.block_length);
            println!("Original Length: {}", enhanced.original_length);
            println!("Content Length: {}", enhanced.content.len());
            println!("--- End of Enhanced Packet ---");
        }
        PcapNgBlock::NameResolution(name_res) => {
            println!("--- Name Resolution Block ---");
            println!("Block Length: {}", name_res.block_length);
            if let Some(options) = &name_res.options {
                println!("Options: {:?}", options);
            } else {
                println!("No options");
            }
            println!("--- End of Name Resolution Block ---");
        }
    }
}

fn debug_section_header(section_header: &SectionHeaderBlock) {
    println!("Section Header Block:");
    println!("  Block Length: {}", section_header.block_length);
    println!("  Byte Order: {:?}", section_header.byte_order);
    println!("  Version: {:?}", section_header.version);
    if let Some(length) = section_header.section_length {
        println!("  Section Length: {}", length);
    } else {
        println!("  Section Length: None (indefinite length)");
    }
    if let Some(options) = &section_header.options {
        println!("  Options: {:?}", options);
    } else {
        println!("  No options");
    }
}
