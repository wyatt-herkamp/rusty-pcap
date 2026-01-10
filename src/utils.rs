use std::io::Read;
/// A reader that allows peaking into the first N bytes without consuming them
pub struct PeakableReader<R: Read> {
    inner: R,
    peeked: Option<Vec<u8>>,
}
impl<R: Read> PeakableReader<R> {
    /// Creates a new `PeakableReader` that reads the first `peek_size` bytes
    pub fn new(mut inner: R, peek_size: usize) -> std::io::Result<Self> {
        let mut peeked = vec![0u8; peek_size];
        let n = inner.read(&mut peeked)?;
        peeked.truncate(n);
        Ok(Self {
            inner,
            peeked: Some(peeked),
        })
    }
    /// Returns a reference to the peeked bytes
    pub fn peak(&self) -> Option<&[u8]> {
        self.peeked.as_deref()
    }
}
impl<R: Read> Read for PeakableReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(peeked) = &mut self.peeked {
            let to_read = std::cmp::min(buf.len(), peeked.len());
            buf[..to_read].copy_from_slice(&peeked[..to_read]);
            if to_read == peeked.len() {
                self.peeked = None;
            } else {
                *peeked = peeked[to_read..].to_vec();
            }
            Ok(to_read)
        } else {
            self.inner.read(buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use crate::utils::PeakableReader;

    #[test]
    fn test_peak_reader() {
        let data = b"Hello, world!";

        let mut reader = PeakableReader::new(&data[..], 5).unwrap();
        let peak = reader.peak().unwrap();
        assert_eq!(peak, b"Hello");

        let mut buffer = [0u8; 5];
        let n = reader.read(&mut buffer).unwrap();
        assert_eq!(n, 5);

        assert_eq!(&buffer, b"Hello");

        let n = reader.read(&mut buffer).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&buffer, b", wor");
    }
}
