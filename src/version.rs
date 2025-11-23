use crate::byte_order::ByteOrder;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Version {
    major: u16,
    minor: u16,
}
impl Version {
    /// Parses the version from the bytes
    #[inline(always)]
    pub(crate) fn parse(bytes: &[u8], byte_order: impl ByteOrder) -> Self {
        let major = byte_order.u16_from_bytes([bytes[0], bytes[1]]);
        let minor = byte_order.u16_from_bytes([bytes[2], bytes[3]]);
        Self { major, minor }
    }
}
