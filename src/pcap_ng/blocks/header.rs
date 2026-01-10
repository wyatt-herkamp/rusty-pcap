use std::io::Read;

use crate::{
    Version,
    byte_order::{ByteOrder, Endianness, ReadExt},
    pcap_ng::{
        PCAP_NG_MAGIC, PcapNgParseError,
        blocks::{Block, BlockHeader},
        options::{BlockOptions, define_options_enum},
    },
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

    fn read_with_header<R: Read>(
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
    /// Reads the entire block from the reader
    pub fn read_from_reader<R: Read>(reader: &mut R) -> Result<Self, PcapNgParseError> {
        let header = BlockHeader::read(reader)?;
        Self::read_with_header::<_>(reader, &header, None)
    }
}
#[cfg(feature = "tokio-async")]
mod tokio_async {
    use crate::{
        Version,
        byte_order::{ByteOrder, Endianness, tokio_async::AsyncReadExt},
        pcap_ng::{
            PcapNgParseError,
            blocks::{BlockHeader, SectionHeaderBlock, tokio_block::TokioAsyncBlock},
            options::BlockOptions,
        },
    };

    impl TokioAsyncBlock for SectionHeaderBlock {
        async fn async_read_with_header<R: tokio::io::AsyncRead + Unpin>(
            reader: &mut R,
            header: &BlockHeader,
            _byte_order: Option<Endianness>,
        ) -> Result<Self, PcapNgParseError>
        where
            Self: Sized,
        {
            header.matches_block_id::<Self>()?;
            let header_data = reader.read_bytes::<16>().await?;

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
                Some(BlockOptions::read_async(reader, byte_order).await?)
            } else {
                None
            };
            reader.read_bytes::<4>().await?;
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
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_parse() -> anyhow::Result<()> {
        let content = [
            10, 13, 13, 10, 96, 0, 0, 0, 77, 60, 43, 26, 1, 0, 0, 0, 255, 255, 255, 255, 255, 255,
            255, 255, 2, 0, 9, 0, 65, 112, 112, 108, 101, 32, 77, 66, 80, 0, 0, 0, 3, 0, 12, 0, 79,
            83, 45, 88, 32, 49, 48, 46, 49, 48, 46, 53, 4, 0, 15, 0, 112, 99, 97, 112, 95, 119,
            114, 105, 116, 101, 114, 46, 108, 117, 97, 0, 1, 0, 7, 0, 116, 101, 115, 116, 48, 48,
            49, 0, 0, 0, 0, 0, 96, 0, 0, 0,
        ];
        let mut reader = std::io::Cursor::new(&content);

        let block = SectionHeaderBlock::read_from_reader(&mut reader)?;
        assert_eq!(block.block_length, 96);
        assert_eq!(block.byte_order, Endianness::LittleEndian);
        assert_eq!(block.version.major, 1);
        assert_eq!(block.version.minor, 0);
        assert_eq!(block.section_length, None);
        assert!(block.options.is_some());
        let options = block.options.unwrap();
        assert_eq!(options.0.len(), 4);
        assert_eq!(options.0[0].code, SHBOptionCodes::Hardware as u16);
        assert_eq!(options.0[0].length, 9);
        assert_eq!(options.0[0].value, b"Apple MBP");
        assert_eq!(options.0[1].code, SHBOptionCodes::OS as u16);
        assert_eq!(options.0[1].length, 12);
        assert_eq!(options.0[1].value, b"OS-X 10.10.5");
        assert_eq!(options.0[2].code, SHBOptionCodes::UserApplication as u16);
        assert_eq!(options.0[2].length, 15);
        assert_eq!(options.0[2].value, b"pcap_writer.lua");
        assert_eq!(options.0[3].code, 1);
        assert_eq!(options.0[3].length, 7);
        assert_eq!(options.0[3].value, b"test001");

        assert_eq!(
            reader.position(),
            96,
            "Reader should be at the end of the block"
        );
        Ok(())
    }
}
