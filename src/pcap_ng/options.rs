use crate::{
    byte_order::{ByteOrder, Endianness, ReadExt},
    pcap_ng::pad_length_to_32_bytes,
};
use std::io::Read;
use thiserror::Error;

macro_rules! define_options_enum {
    (
        $(#[$docs:meta])*
        enum $name:ident {
            $(
                $(#[$variant_docs:meta])*
                $variant:ident = $value:literal,
            )*
        }
    ) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $(#[$docs])*
        pub enum $name {
            $(
                $(#[$variant_docs])*
                $variant = $value,
            )*
        }

        impl TryFrom<u16> for $name {
            type Error = ();

            fn try_from(value: u16) -> Result<Self, Self::Error> {
                match value {
                    $(
                        $value => Ok(Self::$variant),
                    )*
                    _ => return Err(()),
                }
            }
        }

    };
}
pub(crate) use define_options_enum;
define_options_enum! {
    enum StandardOptions{
        Comment = 1,
        CustomUTF8Copied = 2988,
        CustomBinaryCopied = 2989,
        CustomUTF8NotCopied = 19372,
        CustomBinaryNotCopied = 19373,
    }
}
impl StandardOptions {
    pub fn is_custom(&self) -> bool {
        matches!(
            self,
            Self::CustomBinaryCopied
                | Self::CustomBinaryNotCopied
                | Self::CustomUTF8Copied
                | Self::CustomUTF8NotCopied
        )
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockOption {
    pub option_code: u16,
    pub option_length: u16,
    /// Private Enterprise Number (PEN)
    ///
    /// Only present if the option is a custom option
    pub pen: Option<u32>,
    pub option_value: Vec<u8>,
}
#[derive(Debug, Error)]
pub enum OptionParseError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    UnexpectedSize(#[from] crate::byte_order::UnexpectedSize),
}
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockOptions(pub Vec<BlockOption>);
impl BlockOptions {
    fn read_option_header<R: Read, B: ByteOrder>(
        reader: &mut R,
        byte_order: B,
    ) -> Result<Option<(u16, u16, Option<u32>)>, OptionParseError> {
        let option_code = reader.read_u16(byte_order)?;
        let option_length = reader.read_u16(byte_order)?;

        if option_code == 0 && option_length == 0 {
            return Ok(None); // No more options to read
        }

        let pen = match StandardOptions::try_from(option_code) {
            Ok(option) if option.is_custom() => Some(reader.read_u32(byte_order)?),
            _ => None, // Skip unknown options
        };
        Ok(Some((option_code, option_length, pen)))
    }

    pub fn read_in<R: Read, B: ByteOrder>(
        &mut self,
        reader: &mut R,
        endianness: B,
    ) -> Result<(), OptionParseError> {
        loop {
            let Some((option_code, option_length, pen)) =
                Self::read_option_header(reader, endianness)?
            else {
                break; // No more options to read
            };

            let padded_length = pad_length_to_32_bytes(option_length as usize);
            let mut option_value = vec![0u8; padded_length];
            reader.read_exact(&mut option_value)?;
            option_value.truncate(option_length as usize);

            self.0.push(BlockOption {
                option_code,
                option_length,
                pen,
                option_value,
            });
        }
        Ok(())
    }
    pub fn read<R: Read>(reader: &mut R, endianness: Endianness) -> Result<Self, OptionParseError> {
        let mut options = Self::default();
        options.read_in(reader, endianness)?;
        Ok(options)
    }

    pub fn read_option<R: Read>(
        reader: &mut R,
        endianness: Endianness,
    ) -> Result<Option<Self>, OptionParseError> {
        let mut options = Self::default();
        options.read_in(reader, endianness)?;
        if options.0.is_empty() {
            return Ok(None);
        }
        Ok(Some(options))
    }
}
