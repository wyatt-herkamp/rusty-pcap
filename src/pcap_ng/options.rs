//! Block Options for pcap-ng files
//!
//! See [3.5 Options](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-options) for more details
use crate::{
    byte_order::{ByteOrder, ReadExt, WriteExt},
    pcap_ng::pad_length_to_32_bytes,
};
use std::io::{Read, Write};
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
    /// Standard options for pcap-ng blocks
    ///
    /// [3.5 Options](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#figure-7)
    enum StandardOptions{
        /// The opt_endofopt option is used to indicate the end of the options for a block.
        ///
        /// This option is not actually present in the options list, but is used to indicate the end of the options.
        EndOfOpt = 0,
        /// The opt_comment option is a UTF-8 string containing human-readable comment text that is associated to the current block.
        /// Line separators SHOULD be a carriage-return + linefeed ('\r\n') or just linefeed ('\n'); either form may appear and be considered a line separator.
        /// The string is not zero-terminated
        Comment = 1,
        /// This option code identifies a Custom Option containing a UTF-8 string in the Custom Data portion.
        ///  The string is not zero-terminated. This Custom Option can be safely copied to a new file if the pcapng file is manipulated by an application;
        /// otherwise 19372 should be used instead.
        CustomUTF8Copied = 2988,
        ///This option code identifies a Custom Option containing binary octets in the Custom Data portion.
        /// This Custom Option can be safely copied to a new file if the pcapng file is manipulated by an application; otherwise 19372 should be used instead.
        CustomBinaryCopied = 2989,
        /// This option code identifies a Custom Option containing a UTF-8 string in the Custom Data portion.
        /// The string is not zero-terminated.
        /// This Custom Option should not be copied to a new file if the pcapng file is manipulated by an application.
        CustomUTF8NotCopied = 19372,
        /// This option code identifies a Custom Option containing binary octets in the Custom Data portion.
        /// This Custom Option should not be copied to a new file if the pcapng file is manipulated by an application.
        CustomBinaryNotCopied = 19373,
    }
}
impl StandardOptions {
    /// Returns true if the option is a custom option
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
    /// Option code
    pub code: u16,
    /// Length of the option value in bytes
    pub length: u16,
    /// Private Enterprise Number (PEN)
    ///
    /// Only present if the option is a custom option
    pub pen: Option<u32>,
    /// The value of the option
    pub value: Vec<u8>,
}
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidOption {
    #[error("Custom option requires a Private Enterprise Number (PEN)")]
    CustomRequiresPen,
    #[error(
        "Option code {0} is not a custom option, but a Private Enterprise Number (PEN) was provided"
    )]
    UnexpectedPen(u16),
}
impl BlockOption {
    /// Creates a new BlockOption
    ///
    /// Pen can only be set if the option code is a custom option.
    pub fn new(
        option_code: u16,
        pen: Option<u32>,
        option_value: impl Into<Vec<u8>>,
    ) -> Result<Self, InvalidOption> {
        if let Ok(option_code) = StandardOptions::try_from(option_code) {
            if option_code.is_custom() && pen.is_none() {
                return Err(InvalidOption::CustomRequiresPen);
            } else if !option_code.is_custom() && pen.is_some() {
                return Err(InvalidOption::UnexpectedPen(option_code as u16));
            }
        } else if pen.is_some() {
            return Err(InvalidOption::UnexpectedPen(option_code));
        }
        let option_value = option_value.into();
        let option_length = option_value.len() as u16;
        let result = Self {
            code: option_code,
            length: option_length,
            pen,
            value: option_value,
        };
        Ok(result)
    }
    pub fn padding_length(&self) -> usize {
        pad_length_to_32_bytes(self.length as usize) - self.length as usize
    }
}
#[derive(Debug, Error)]
pub enum OptionParseError {
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    UnexpectedSize(#[from] crate::byte_order::UnexpectedSize),
}
/// Represents a collection of options for a block
///
/// [3.5 Options](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-options)
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
        byte_order: B,
    ) -> Result<(), OptionParseError> {
        loop {
            let Some((option_code, option_length, pen)) =
                Self::read_option_header(reader, byte_order)?
            else {
                break; // No more options to read
            };

            let padded_length = pad_length_to_32_bytes(option_length as usize);
            let mut option_value = vec![0u8; padded_length];
            reader.read_exact(&mut option_value)?;
            option_value.truncate(option_length as usize);

            self.0.push(BlockOption {
                code: option_code,
                length: option_length,
                pen,
                value: option_value,
            });
        }
        Ok(())
    }
    pub fn read<R: Read, B: ByteOrder>(
        reader: &mut R,
        byte_order: B,
    ) -> Result<Self, OptionParseError> {
        let mut options = Self::default();
        options.read_in(reader, byte_order)?;
        Ok(options)
    }

    pub fn read_option<R: Read, B: ByteOrder>(
        reader: &mut R,
        byte_order: B,
    ) -> Result<Option<Self>, OptionParseError> {
        let mut options = Self::default();
        options.read_in(reader, byte_order)?;
        if options.0.is_empty() {
            return Ok(None);
        }
        Ok(Some(options))
    }

    pub fn write<W: Write>(
        &self,
        writer: &mut W,
        byte_order: impl ByteOrder,
    ) -> Result<(), std::io::Error> {
        for option in &self.0 {
            writer.write_u16(option.code, byte_order)?;
            writer.write_u16(option.length, byte_order)?;

            if let Some(pen) = option.pen {
                writer.write_u32(pen, byte_order)?;
            }
            writer.write_all(&option.value)?;
            // Pad to 32 bytes
            let padding = option.padding_length();
            if padding > 0 {
                writer.write_all(&vec![0; padding])?;
            }
        }
        writer.write_u16(0, byte_order)?; // End of options
        writer.write_u16(0, byte_order)?; // End of options length
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::byte_order::LittleEndian;

    #[test]
    fn test_block_options_read_write() {
        let option_one = BlockOption::new(1, None, b"Test comment").unwrap();
        assert_eq!(option_one.code, 1);
        assert_eq!(option_one.length, 12);
        assert_eq!(option_one.value, b"Test comment");
        assert!(option_one.pen.is_none());
        assert_eq!(option_one.padding_length(), 0);

        let option_two = BlockOption::new(2, None, b"Custom data").unwrap();
        assert_eq!(option_two.code, 2);
        assert_eq!(option_two.length, 11);
        assert_eq!(option_two.value, b"Custom data");
        assert_eq!(option_two.pen, None);
        assert_eq!(option_two.padding_length(), 1);

        let options = BlockOptions(vec![option_one, option_two]);

        let mut buffer = Vec::new();
        options.write(&mut buffer, LittleEndian).unwrap();
        let expected_result = [
            1, 0, 12, 0, 84, 101, 115, 116, 32, 99, 111, 109, 109, 101, 110, 116, 2, 0, 11, 0, 67,
            117, 115, 116, 111, 109, 32, 100, 97, 116, 97, 0, 0, 0, 0, 0,
        ];
        assert_eq!(buffer, expected_result);

        let read_options = BlockOptions::read(&mut buffer.as_slice(), LittleEndian).unwrap();
        assert_eq!(options, read_options);
    }
}
