use std::io::{Cursor, Read};

use crate::{
    byte_order::{Endianness, ReadExt, UndertminedByteOrder},
    link_type::LinkType,
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
        options::BlockOptions,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceDescriptionBlock {
    pub block_length: u32,
    pub link_type: LinkType,
    pub reserved: [u8; 2],
    pub snap_length: u32,
    pub options: Option<BlockOptions>,
}
impl Block for InterfaceDescriptionBlock {
    fn block_id() -> u32 {
        1
    }
    fn block_id_le() -> [u8; 4] {
        [0x01, 0x00, 0x00, 0x00] // Interface ID for SHB
    }
    fn block_id_be() -> [u8; 4] {
        [0x00, 0x00, 0x00, 0x01] //  Interface ID for SHB
    }
    fn minimum_size() -> usize {
        16
    }

    fn read_with_header<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Option<Endianness>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized,
    {
        header.matches_block_id::<Self>()?;
        let byte_order = byte_order
            .or(header.endianess_from_block::<Self>())
            .ok_or(UndertminedByteOrder)?;
        let mut cursor = Cursor::new(reader.read_bytes::<8>()?);

        let link_type = LinkType::try_from(cursor.read_u16(byte_order)?)?;
        let reserved = cursor.read_bytes::<2>()?;
        let snap_length = cursor.read_u32(byte_order)?;

        let block_length = header.block_length_as_u32(byte_order);
        let options_space = block_length as usize - 12;
        let options = if options_space > 0 {
            BlockOptions::read_option(reader, byte_order)?
        } else {
            None
        };

        reader.read_bytes::<4>()?;
        Ok(Self {
            block_length,
            link_type,
            reserved,
            snap_length,
            options,
        })
    }
}
impl InterfaceDescriptionBlock {
    pub fn read<R: Read>(reader: &mut R, byte_order: Endianness) -> Result<Self, PcapNgParseError> {
        let header = BlockHeader::read(reader)?;
        Self::read_with_header::<_>(reader, &header, Some(byte_order))
    }
}

#[cfg(test)]
mod tests {
    use std::{fs::File, io::Seek};

    use crate::pcap_ng::blocks::{
        header::SectionHeaderBlock, interface::InterfaceDescriptionBlock,
    };

    #[test]
    fn read_from_file() -> anyhow::Result<()> {
        let mut file = File::open("test_data/ng/test001_le.pcapng")?;
        let block_header = SectionHeaderBlock::read_from_reader(&mut file)?;
        //println!("Block Header: {:?}", block_header);
        println!("Reading Interface Description Block...");

        let interface_block = InterfaceDescriptionBlock::read(&mut file, block_header.byte_order)?;
        println!("Interface Block: {:?}", interface_block);
        let Some(options) = interface_block.options else {
            panic!("No options found in the interface block");
        };
        for option in options.0 {
            println!(
                "Option Code: {}, Length: {}",
                option.option_code, option.option_length
            );
            //let code = SHBOptionCodes::try_from(option.option_code);
            //println!("Parsed Option Code: {:?}", code);

            match String::from_utf8(option.option_value.clone()) {
                Ok(ok) => {
                    println!("Parsed Option Value: {}", ok);
                }
                Err(_) => {
                    println!("Parsed Option Value: {:?}", option.option_value);
                }
            };
        }
        let cursor_pos = file.stream_position()?;
        println!("Current file position: {}", cursor_pos);
        Ok(())
    }
}
