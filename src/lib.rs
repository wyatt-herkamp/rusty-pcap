#![forbid(unsafe_code)]
//! rusty-pcap is a pcap library for Rust
//!
//! 100% Rust implementation of a pcap reader
use std::io::Write;

use crate::{
    byte_order::{ByteOrder, WriteExt},
    pcap::file_header::MagicNumberAndEndianness,
    pcap_ng::PCAP_NG_MAGIC,
};

pub mod byte_order;
pub mod link_type;
pub mod pcap;
pub mod pcap_ng;

/// PcapFileType is the type of the pcap file, either Pcap or PcapNg
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapFileType {
    /// Pcap file format
    ///
    /// Based on the libpcap format
    Pcap,
    /// PcapNg file format
    PcapNg,
}
impl PcapFileType {
    /// Returns the PcapFileType from the magic number
    pub fn from_magic(magic: [u8; 4]) -> Option<Self> {
        if MagicNumberAndEndianness::try_from(magic).is_ok() {
            Some(PcapFileType::Pcap)
        } else if magic == PCAP_NG_MAGIC {
            Some(PcapFileType::PcapNg)
        } else {
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}
impl Version {
    /// Parses the version from the bytes
    #[inline(always)]
    pub(crate) fn parse(bytes: &[u8], byte_order: impl ByteOrder) -> Self {
        let major = byte_order.u16_from_bytes([bytes[0], bytes[1]]);
        let minor = byte_order.u16_from_bytes([bytes[2], bytes[3]]);
        Self { major, minor }
    }
    pub(crate) fn write<W: Write>(
        &self,
        target: &mut W,
        byte_order: impl ByteOrder,
    ) -> Result<(), std::io::Error> {
        target.write_u16(self.major, byte_order)?;
        target.write_u16(self.minor, byte_order)?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod test_helpers {
    use std::{
        fs::{File, create_dir_all},
        io::Read,
        path::{Path, PathBuf},
    };

    use anyhow::{Result, anyhow};

    pub fn test_target_dir() -> Result<PathBuf> {
        let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let target_dir = base_dir.join("test_data/actual");

        if !target_dir.exists() {
            create_dir_all(&target_dir)?;
        }
        Ok(target_dir)
    }
    pub fn test_expected_dir() -> Result<PathBuf> {
        let base_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

        let target_dir = base_dir.join("test_data/expected");

        if !target_dir.exists() {
            create_dir_all(&target_dir)?;
        }
        Ok(target_dir)
    }

    pub fn test_files(test_file_name: &str) -> Result<(PathBuf, PathBuf)> {
        let test_actual = test_target_dir()?.join(test_file_name);
        let test_expected = test_expected_dir()?.join(test_file_name);
        Ok((test_actual, test_expected))
    }
    #[track_caller]
    pub fn do_files_match(actual: impl AsRef<Path>, expected: impl AsRef<Path>) -> Result<()> {
        if !expected.as_ref().exists() {
            println!("Expected Does not exist coppying actual over");
            std::fs::copy(actual, expected)?;
            return Err(anyhow!(
                "No Expected File existed. But this is just to signal that you a new file was generated"
            ));
        }
        let mut actual_file = File::open(actual)?;
        let mut expected_file = File::open(expected)?;
        let mut actual_bytes = Vec::with_capacity(actual_file.metadata()?.len() as usize);
        let mut expected_bytes = Vec::with_capacity(actual_file.metadata()?.len() as usize);

        actual_file.read_to_end(&mut actual_bytes)?;
        expected_file.read_to_end(&mut expected_bytes)?;

        assert_eq!(actual_bytes, expected_bytes);

        Ok(())
    }
}
