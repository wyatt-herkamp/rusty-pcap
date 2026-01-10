use std::io::{Cursor, Read};

use crate::{
    byte_order::{Endianness, ReadExt, UndertminedByteOrder},
    link_type::LinkType,
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
        options::{BlockOptions, define_options_enum},
    },
};
define_options_enum! {
    /// Options for the Interface Description Block
    enum InterfaceOptionCodes {
        /// The if_name option is a UTF-8 string containing the name of the device used to capture data. The string is not zero-terminated.
        IfName = 2,
        /// The if_description option is a UTF-8 string containing the description of the device used to capture data. The string is not zero-terminated.
        IfDescription = 3,
        IfIPv4Address = 4,
        IfIPv6Address = 5,
        IfMACAddress = 6,
        IfEuiAddr = 7,
        /// The if_speed option is a 64-bit unsigned value indicating the interface speed, in bits per second.
        IfSpeed = 8,
        IfTimestampResolution = 9,
        IfTZone = 10,
        IfFilter = 11,
        IfOS = 12,
        IfFcsLength = 13,
        IfTsOffset = 14,
        IfHardware = 15,
        IfTxSpeed = 16,
        IfRxSpeed = 17,
    }
}

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
        // 12 base + 2 for link_type + 2 for reserved + 4 for snap_length
        20
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
            .or(header.endianness_from_block::<Self>())
            .ok_or(UndertminedByteOrder)?;
        let mut cursor = Cursor::new(reader.read_bytes::<8>()?);

        let link_type = LinkType::try_from(cursor.read_u16(byte_order)?)?;
        let reserved = cursor.read_bytes::<2>()?;
        let snap_length = cursor.read_u32(byte_order)?;

        let block_length = header.block_length_as_u32(byte_order);
        let options_space = block_length as usize - Self::minimum_size();

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
#[cfg(feature = "tokio-async")]
mod tokio_async {
    use crate::pcap_ng::blocks::{InterfaceDescriptionBlock, tokio_block::TokioAsyncBlock};

    impl TokioAsyncBlock for InterfaceDescriptionBlock {}
}
impl InterfaceDescriptionBlock {
    pub fn read<R: Read>(reader: &mut R, byte_order: Endianness) -> Result<Self, PcapNgParseError> {
        let header = BlockHeader::read(reader)?;
        Self::read_with_header::<_>(reader, &header, Some(byte_order))
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        byte_order::Endianness,
        pcap_ng::blocks::{InterfaceOptionCodes, interface::InterfaceDescriptionBlock},
    };
    #[test]
    fn parse_bytes() -> anyhow::Result<()> {
        let content = [
            1, 0, 0, 0, 52, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 2, 0, 24, 0, 115, 105, 108, 108, 121,
            32, 101, 116, 104, 101, 114, 110, 101, 116, 32, 105, 110, 116, 101, 114, 102, 97, 99,
            101, 0, 0, 0, 0, 52, 0, 0, 0,
        ];
        let mut reader = std::io::Cursor::new(&content);
        let interface = InterfaceDescriptionBlock::read(&mut reader, Endianness::LittleEndian)?;

        assert_eq!(interface.block_length, 52);
        assert_eq!(interface.link_type, crate::link_type::LinkType::Ethernet);
        assert_eq!(interface.reserved, [0, 0]);
        assert_eq!(interface.snap_length, 0);
        assert!(interface.options.is_some());
        let options = interface.options.unwrap();
        assert_eq!(options.0.len(), 1);
        assert_eq!(options.0[0].code, 2);
        assert_eq!(
            InterfaceOptionCodes::try_from(options.0[0].code),
            Ok(InterfaceOptionCodes::IfName)
        );
        assert_eq!(options.0[0].length, 24);
        assert_eq!(options.0[0].value, b"silly ethernet interface");

        assert_eq!(reader.position(), 52);
        Ok(())
    }
}
