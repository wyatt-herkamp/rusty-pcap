use crate::{
    byte_order::{ByteOrder, Endianness, ReadExt},
    pcap_ng::{
        PCAP_NG_MAGIC, PcapNgParseError,
        blocks::{Block, BlockHeader},
        options::{BlockOptions, define_options_enum},
    },
    version::Version,
};
define_options_enum! {
    enum SHBOptionCodes {
        Hardware = 2,
        OS = 3,
        UserApplication = 4,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectionHeaderBlock {
    pub block_length: u32,
    pub byte_order: Endianness,
    pub version: Version,
    /// If negative -1 it will be treated as no section length
    pub section_length: Option<u64>,
    pub options: Option<BlockOptions>,
}
impl Block for SectionHeaderBlock {
    fn block_id() -> u32 {
        168627466
    }
    fn block_id_le() -> [u8; 4] {
        PCAP_NG_MAGIC // SHB block ID
    }
    fn block_id_be() -> [u8; 4] {
        PCAP_NG_MAGIC // SHB block ID
    }
    fn minimum_size() -> usize {
        24 // Minimum size for a Section Header Block
    }

    fn read_with_header<R: std::io::Read>(
        reader: &mut R,
        header: &BlockHeader,
        _byte_order: Option<Endianness>,
    ) -> Result<Self, PcapNgParseError>
    where
        Self: Sized,
    {
        header.matches_block_id::<Self>()?;
        let header_data = reader.read_bytes::<16>()?;
        let byte_order = Endianness::from_pcap_ng_bytes(&[
            header_data[0],
            header_data[1],
            header_data[2],
            header_data[3],
        ])?;
        let block_length = header.block_length_as_u32(byte_order);
        let version = Version::parse(&header_data[4..8], byte_order);
        let section_length: [u8; 8] = header_data[8..16].try_into()?;
        let section_length = if section_length == [0xFF; 8] {
            None // No section length
        } else {
            Some(byte_order.u64_from_bytes(section_length))
        };

        let options_space = block_length as usize - 24;
        let options = if options_space > 0 {
            BlockOptions::read_option(reader, byte_order)?
        } else {
            None
        };
        reader.read_bytes::<4>()?;
        let result = Self {
            block_length,
            byte_order,
            version,
            section_length,
            options,
        };
        Ok(result)
    }
}
impl SectionHeaderBlock {
    pub fn read_from_reader<R: std::io::Read>(reader: &mut R) -> Result<Self, PcapNgParseError> {
        let header = BlockHeader::read(reader)?;
        Self::read_with_header::<_>(reader, &header, None)
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;

    use super::*;

    #[test]
    fn read_from_file() -> anyhow::Result<()> {
        let mut file = File::open("test_data/ng/test001_le.pcapng")?;
        let block_header = SectionHeaderBlock::read_from_reader(&mut file)?;
        //println!("Block Header: {:?}", block_header);
        let Some(options) = block_header.options else {
            panic!("No options found in the block header");
        };
        for option in options.0 {
            println!(
                "Option Code: {}, Length: {}",
                option.option_code, option.option_length
            );
            let code = SHBOptionCodes::try_from(option.option_code);
            println!("Parsed Option Code: {:?}", code);

            match String::from_utf8(option.option_value.clone()) {
                Ok(ok) => {
                    println!("Parsed Option Value: {}", ok);
                }
                Err(_) => {
                    println!("Parsed Option Value: {:?}", option.option_value);
                }
            };
        }
        Ok(())
    }
}
