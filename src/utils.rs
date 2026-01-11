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

#[cfg(feature = "tokio-async")]
pub mod tokio_impl {
    use tokio::io::{AsyncRead, AsyncReadExt as _};

    /// A reader that allows peaking into the first N bytes without consuming them
    pub struct AsyncPeakableReader<R: AsyncRead + Unpin> {
        inner: R,
        peeked: Option<Vec<u8>>,
    }
    impl<R: AsyncRead + Unpin> AsyncPeakableReader<R> {
        /// Creates a new `AsyncPeakableReader` that reads the first `peek_size` bytes
        pub async fn new(mut inner: R, peek_size: usize) -> std::io::Result<Self> {
            let mut peeked = vec![0u8; peek_size];
            let n = inner.read(&mut peeked).await?;
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
    impl<R: AsyncRead + Unpin> AsyncRead for AsyncPeakableReader<R> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            if let Some(peeked) = &mut self.peeked {
                let to_read = std::cmp::min(buf.remaining(), peeked.len());
                buf.put_slice(&peeked[..to_read]);
                if to_read == peeked.len() {
                    self.peeked = None;
                } else {
                    *peeked = peeked[to_read..].to_vec();
                }
                std::task::Poll::Ready(Ok(()))
            } else {
                std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
            }
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
