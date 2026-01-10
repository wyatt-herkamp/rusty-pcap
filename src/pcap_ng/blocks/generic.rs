use std::io::Read;

use crate::{
    byte_order::{Endianness, ReadExt},
    pcap_ng::{PcapNgParseError, blocks::BlockHeader},
};
/// A Generic Block in the PCAP-NG format
///
/// Used for unknown block ids or custom blocks that do not have a specific structure defined in the PCAP-NG specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericBlock {
    /// The block ID
    pub block_id: u32,
    /// The length of the block in bytes, including the header
    pub block_length: u32,
    /// The data of the block, if any
    pub data: Option<Vec<u8>>,
}
impl GenericBlock {
    pub fn new(block_id: u32, data: Option<Vec<u8>>) -> Self {
        let mut block_length = 12; // Minimum size for a block header
        if let Some(ref data) = data {
            block_length += data.len() as u32;
        }
        Self {
            block_id,
            block_length,
            data,
        }
    }
    pub fn read_with_header<R: Read>(
        reader: &mut R,
        header: &BlockHeader,
        byte_order: Endianness,
    ) -> Result<Self, PcapNgParseError> {
        let block_length = header.block_length_as_u32(byte_order);
        let data = if block_length > 12 {
            let mut data = vec![0u8; (block_length - 12) as usize];
            reader.read_exact(&mut data)?;
            Some(data)
        } else {
            None
        };

        reader.read_bytes::<4>()?;
        Ok(Self {
            block_id: header.block_id_as_u32(byte_order),
            block_length,
            data,
        })
    }
    pub fn read<R: Read>(reader: &mut R, byte_order: Endianness) -> Result<Self, PcapNgParseError> {
        let header = BlockHeader::read(reader)?;
        Self::read_with_header(reader, &header, byte_order)
    }
}

#[cfg(feature = "tokio-async")]
mod tokio_async {
    use tokio::io::{AsyncRead, AsyncReadExt as _};

    use crate::{
        byte_order::{Endianness, tokio_async::AsyncReadExt as _},
        pcap_ng::{
            PcapNgParseError,
            blocks::{BlockHeader, GenericBlock},
        },
    };

    impl GenericBlock {
        pub async fn read_async_with_header<R: AsyncRead + Unpin>(
            reader: &mut R,
            header: &BlockHeader,
            byte_order: Endianness,
        ) -> Result<Self, PcapNgParseError> {
            let block_length = header.block_length_as_u32(byte_order);
            let data = if block_length > 12 {
                let mut data = vec![0u8; (block_length - 12) as usize];
                reader.read_exact(&mut data).await?;
                Some(data)
            } else {
                None
            };

            reader.read_bytes::<4>().await?;
            Ok(Self {
                block_id: header.block_id_as_u32(byte_order),
                block_length,
                data,
            })
        }
    }
}
