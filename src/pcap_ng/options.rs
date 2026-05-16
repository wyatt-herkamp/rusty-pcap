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
/// A single TLV option attached to a pcap-ng block.
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
/// Errors returned by [`BlockOption::new`] when a PEN is supplied
/// inconsistently with the option code.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum InvalidOption {
    /// A custom option code was used without supplying a PEN.
    #[error("Custom option requires a Private Enterprise Number (PEN)")]
    CustomRequiresPen,
    /// A PEN was supplied for an option code that is not custom.
    #[error(
        "Option code {0} is not a custom option, but a Private Enterprise Number (PEN) was provided"
    )]
    UnexpectedPen(u16),
}
impl BlockOption {
    /// Creates a new BlockOption
    ///
    /// `pen` may only be set for custom-option codes (2988, 2989, 19372, 19373).
    /// When `pen` is set, the wire-format option length is `4 + value.len()`
    /// because the pcapng spec includes the PEN in the option length
    /// (see RFC pcapng §3.5.2).
    pub fn new(
        option_code: u16,
        pen: Option<u32>,
        option_value: impl Into<Vec<u8>>,
    ) -> Result<Self, InvalidOption> {
        let is_custom_code = StandardOptions::try_from(option_code)
            .map(|o| o.is_custom())
            .unwrap_or(false);
        if pen.is_some() && !is_custom_code {
            return Err(InvalidOption::UnexpectedPen(option_code));
        }
        let option_value = option_value.into();
        let option_length = if pen.is_some() {
            (option_value.len() + 4) as u16
        } else {
            option_value.len() as u16
        };
        let result = Self {
            code: option_code,
            length: option_length,
            pen,
            value: option_value,
        };
        Ok(result)
    }
    /// Returns the number of padding bytes required to align the option to
    /// a 4-byte (32-bit) boundary.
    pub fn padding_length(&self) -> usize {
        pad_length_to_32_bytes(self.length as usize) - self.length as usize
    }
}
/// Errors returned while parsing a block's options list.
#[derive(Debug, Error)]
pub enum OptionParseError {
    /// An underlying I/O error occurred.
    #[error(transparent)]
    IO(#[from] std::io::Error),
    /// A fixed-size field had the wrong number of bytes.
    #[error(transparent)]
    UnexpectedSize(#[from] crate::byte_order::UnexpectedSize),
}
/// Represents a collection of options for a block
///
/// [3.5 Options](https://www.ietf.org/archive/id/draft-tuexen-opsawg-pcapng-03.html#name-options)
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BlockOptions(pub Vec<BlockOption>);
impl BlockOptions {
    /// Decodes a single TLV option from `bytes`, starting at `pos`.
    ///
    /// Returns the parsed option and the new cursor position, or `Ok(None)`
    /// if an end-of-options marker is encountered, the remaining bytes are
    /// too few to hold an option header, or the option claims more bytes
    /// than remain in the buffer. The last case is treated as "stop parsing"
    /// rather than an error because the byte budget is bounded by the
    /// enclosing block-length and overflows mean malformed input.
    fn decode_one<B: ByteOrder>(
        bytes: &[u8],
        pos: usize,
        byte_order: B,
    ) -> Result<Option<(BlockOption, usize)>, OptionParseError> {
        if bytes.len().saturating_sub(pos) < 4 {
            return Ok(None);
        }
        let option_code = byte_order.u16_from_bytes([bytes[pos], bytes[pos + 1]]);
        let option_length = byte_order.u16_from_bytes([bytes[pos + 2], bytes[pos + 3]]);
        if option_code == 0 && option_length == 0 {
            return Ok(None);
        }
        let body_start = pos + 4;
        let padded_length = pad_length_to_32_bytes(option_length as usize);
        if body_start.saturating_add(padded_length) > bytes.len() {
            return Ok(None);
        }
        let body = &bytes[body_start..body_start + padded_length];

        // Per pcapng spec §3.5.2: custom-option Length includes the PEN
        // (i.e. the first 4 bytes of the option body are the PEN). Files
        // written by non-conformant tools may omit the PEN entirely; in
        // those cases the first 4 value bytes get surfaced as the PEN,
        // which is harmless for byte-alignment.
        let is_custom = StandardOptions::try_from(option_code)
            .map(|o| o.is_custom())
            .unwrap_or(false);
        let (pen, value) = if is_custom && option_length >= 4 {
            let pen_bytes = [body[0], body[1], body[2], body[3]];
            let pen = byte_order.u32_from_bytes(pen_bytes);
            let mut value = body[4..option_length as usize].to_vec();
            value.truncate(option_length as usize - 4);
            (Some(pen), value)
        } else {
            let mut value = body[..option_length.min(padded_length as u16) as usize].to_vec();
            value.truncate(option_length as usize);
            (None, value)
        };
        let opt = BlockOption {
            code: option_code,
            length: option_length,
            pen,
            value,
        };
        Ok(Some((opt, body_start + padded_length)))
    }

    /// Reads exactly `max_bytes` from `reader` and parses options out of
    /// that bounded buffer.
    ///
    /// Stops at an end-of-options marker or when the buffer is exhausted.
    /// Used by block readers (SHB, IDB, EPB, NRB) to ensure option parsing
    /// can never overrun the enclosing block-length, even when files omit
    /// the optional end-of-options marker or contain non-conformant
    /// option encodings.
    pub fn read_bounded<R: Read, B: ByteOrder>(
        reader: &mut R,
        byte_order: B,
        max_bytes: usize,
    ) -> Result<Self, OptionParseError> {
        if max_bytes == 0 {
            return Ok(Self::default());
        }
        let mut raw = vec![0u8; max_bytes];
        reader.read_exact(&mut raw)?;
        let mut options = Self::default();
        let mut pos = 0;
        while let Some((opt, next)) = Self::decode_one(&raw, pos, byte_order)? {
            options.0.push(opt);
            pos = next;
        }
        Ok(options)
    }

    /// Like [`read_bounded`](Self::read_bounded) but returns `None` if no
    /// options were parsed (the bounded region was empty or contained only
    /// an end-of-options marker).
    pub fn read_bounded_option<R: Read, B: ByteOrder>(
        reader: &mut R,
        byte_order: B,
        max_bytes: usize,
    ) -> Result<Option<Self>, OptionParseError> {
        let options = Self::read_bounded(reader, byte_order, max_bytes)?;
        if options.0.is_empty() {
            Ok(None)
        } else {
            Ok(Some(options))
        }
    }

    /// Reads options from `reader` until an end-of-options marker is hit.
    ///
    /// Prefer [`read_bounded`](Self::read_bounded) when the caller knows the
    /// block-length: this unbounded variant will read past the current block
    /// if the file omits the end-of-options marker.
    pub fn read_in<R: Read, B: ByteOrder>(
        &mut self,
        reader: &mut R,
        byte_order: B,
    ) -> Result<(), OptionParseError> {
        loop {
            let option_code = reader.read_u16(byte_order)?;
            let option_length = reader.read_u16(byte_order)?;
            if option_code == 0 && option_length == 0 {
                return Ok(());
            }
            let padded_length = pad_length_to_32_bytes(option_length as usize);
            let mut body = vec![0u8; padded_length];
            reader.read_exact(&mut body)?;
            let is_custom = StandardOptions::try_from(option_code)
                .map(|o| o.is_custom())
                .unwrap_or(false);
            let (pen, value) = if is_custom && option_length >= 4 {
                let pen = byte_order.u32_from_bytes([body[0], body[1], body[2], body[3]]);
                let mut value = body[4..option_length as usize].to_vec();
                value.truncate(option_length as usize - 4);
                (Some(pen), value)
            } else {
                body.truncate(option_length as usize);
                (None, body)
            };
            self.0.push(BlockOption {
                code: option_code,
                length: option_length,
                pen,
                value,
            });
        }
    }
    /// Reads a complete options list from `reader` (unbounded).
    pub fn read<R: Read, B: ByteOrder>(
        reader: &mut R,
        byte_order: B,
    ) -> Result<Self, OptionParseError> {
        let mut options = Self::default();
        options.read_in(reader, byte_order)?;
        Ok(options)
    }

    /// Reads an options list and returns `None` if it was empty (unbounded).
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

    /// Writes all options to `writer`, including padding and the
    /// end-of-options marker.
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
#[cfg(feature = "tokio-async")]
mod tokio_async {
    use tokio::io::{AsyncRead, AsyncReadExt as _};

    use crate::{
        byte_order::{ByteOrder, tokio_async::AsyncReadExt as InternalAsyncReadExt},
        pcap_ng::{
            options::{BlockOption, BlockOptions, OptionParseError, StandardOptions},
            pad_length_to_32_bytes,
        },
    };

    impl BlockOptions {
        /// Async counterpart to [`BlockOptions::read_in`] (unbounded).
        pub async fn read_async_in<R: AsyncRead + Unpin, B: ByteOrder>(
            &mut self,
            reader: &mut R,
            byte_order: B,
        ) -> Result<(), OptionParseError> {
            loop {
                let option_code =
                    <R as InternalAsyncReadExt>::read_u16(reader, byte_order).await?;
                let option_length =
                    <R as InternalAsyncReadExt>::read_u16(reader, byte_order).await?;
                if option_code == 0 && option_length == 0 {
                    return Ok(());
                }
                let padded_length = pad_length_to_32_bytes(option_length as usize);
                let mut body = vec![0u8; padded_length];
                reader.read_exact(&mut body).await?;
                let is_custom = StandardOptions::try_from(option_code)
                    .map(|o| o.is_custom())
                    .unwrap_or(false);
                let (pen, value) = if is_custom && option_length >= 4 {
                    let pen = byte_order.u32_from_bytes([body[0], body[1], body[2], body[3]]);
                    let mut value = body[4..option_length as usize].to_vec();
                    value.truncate(option_length as usize - 4);
                    (Some(pen), value)
                } else {
                    body.truncate(option_length as usize);
                    (None, body)
                };
                self.0.push(BlockOption {
                    code: option_code,
                    length: option_length,
                    pen,
                    value,
                });
            }
        }
        /// Async counterpart to [`BlockOptions::read`] (unbounded).
        pub async fn read_async<R: AsyncRead + Unpin, B: ByteOrder>(
            reader: &mut R,
            byte_order: B,
        ) -> Result<Self, OptionParseError> {
            let mut options = Self::default();
            options.read_async_in(reader, byte_order).await?;
            Ok(options)
        }
        /// Async counterpart to [`BlockOptions::read_bounded`].
        ///
        /// Reads exactly `max_bytes` from `reader` and parses options out of
        /// the bounded buffer, stopping at an end-of-options marker or when
        /// the buffer is exhausted. Mirrors the sync version's robustness
        /// against missing end-of-options markers and non-conformant encodings.
        pub async fn read_async_bounded<R: AsyncRead + Unpin, B: ByteOrder>(
            reader: &mut R,
            byte_order: B,
            max_bytes: usize,
        ) -> Result<Self, OptionParseError> {
            if max_bytes == 0 {
                return Ok(Self::default());
            }
            let mut raw = vec![0u8; max_bytes];
            reader.read_exact(&mut raw).await?;
            let mut options = Self::default();
            let mut pos = 0;
            while let Some((opt, next)) = Self::decode_one(&raw, pos, byte_order)? {
                options.0.push(opt);
                pos = next;
            }
            Ok(options)
        }
        /// Like [`read_async_bounded`](Self::read_async_bounded) but returns
        /// `None` if no options were parsed.
        pub async fn read_async_bounded_option<R: AsyncRead + Unpin, B: ByteOrder>(
            reader: &mut R,
            byte_order: B,
            max_bytes: usize,
        ) -> Result<Option<Self>, OptionParseError> {
            let options = Self::read_async_bounded(reader, byte_order, max_bytes).await?;
            if options.0.is_empty() {
                Ok(None)
            } else {
                Ok(Some(options))
            }
        }
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
