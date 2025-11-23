use std::io::Read;

use crate::{
    byte_order::{ByteOrder, Endianness, UndertminedByteOrder},
    pcap_ng::{
        PcapNgParseError,
        blocks::{Block, BlockHeader},
        options::BlockOptions,
        pad_length_to_32_bytes,
    },
};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub record_type: u16,
    pub record_length: u16,
    pub record_data: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Records(pub Vec<Record>);
impl Records {
    pub fn read_from_reader<R: Read, B: ByteOrder>(
        reader: &mut R,
        byte_order: B,
    ) -> Result<(Self, usize), PcapNgParseError> {
        let mut records = Vec::new();
        let mut total_length = 0;
        loop {
            let mut header = [0u8; 4];

            if reader.read_exact(&mut header).is_err() {
                break; // EOF or error
            }
            let record_type = byte_order.u16_from_bytes([header[0], header[1]]);
            let record_length = byte_order.u16_from_bytes([header[2], header[3]]);
            total_length += 4; // Header size
            if record_length == 0 {
                break; // No more records
            }
            let length = record_length as usize;
            let padded_length = pad_length_to_32_bytes(length);
            let mut data = vec![0u8; padded_length];
            reader.read_exact(&mut data)?;
            total_length += padded_length;
            data.truncate(length);
            records.push(Record {
                record_type,
                record_length,
                record_data: data,
            });
        }
        Ok((Self(records), total_length))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NameResolutionBlock {
    pub block_length: u32,
    pub records: Records,
    pub options: Option<BlockOptions>,
}
impl Block for NameResolutionBlock {
    fn block_id() -> u32 {
        4
    }

    fn minimum_size() -> usize {
        12
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
        let block_length = header.block_length_as_u32(byte_order);
        let (records, bytes_read) = Records::read_from_reader(reader, byte_order)?;
        let options_space = block_length as usize - (Self::minimum_size() + bytes_read);
        let options = if options_space > 0 {
            BlockOptions::read_option(reader, byte_order)?
        } else {
            None
        };
        reader.read_exact(&mut [0u8; 4])?; // Read the footer (4 bytes)
        Ok(Self {
            block_length,
            records,
            options,
        })
    }
}
impl NameResolutionBlock {
    pub fn read<R: Read>(reader: &mut R, byte_order: Endianness) -> Result<Self, PcapNgParseError> {
        let header = BlockHeader::read(reader)?;
        Self::read_with_header::<_>(reader, &header, Some(byte_order))
    }
}
