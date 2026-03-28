//! Lock-free buffer pool for async pcap reading with owned packet buffers.
//!
//! Uses a Treiber stack (lock-free atomic stack) for O(1) buffer acquire/release
//! and a [`tokio::sync::Semaphore`] for async waiting when the pool is empty.
#![allow(unsafe_code)]

use std::cell::UnsafeCell;
use std::mem::ManuallyDrop;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicU32, Ordering};

use crate::pcap::packet_header::PacketHeader;

const EMPTY: u32 = u32::MAX;

type BufferSlot = UnsafeCell<Option<Box<[u8]>>>;

/// Pack a (index, tag) pair into a single `u64` for atomic operations.
#[inline(always)]
fn pack(index: u32, tag: u32) -> u64 {
    ((tag as u64) << 32) | (index as u64)
}

/// Unpack a `u64` into (index, tag).
#[inline(always)]
fn unpack(val: u64) -> (u32, u32) {
    (val as u32, (val >> 32) as u32)
}

/// Inner state of the buffer pool, shared via `Arc`.
///
/// Uses an index-based Treiber stack with a 32-bit ABA tag to avoid
/// the ABA problem without pointer-based hazard pointers.
struct BufferPoolInner {
    /// Buffer storage. Each slot holds `Some(buffer)` when on the free stack,
    /// `None` when checked out to a [`PooledPacket`].
    slots: Box<[BufferSlot]>,
    /// Intrusive linked list: `next[i]` is the index of the next free slot after `i`.
    next: Box<[AtomicU32]>,
    /// Packed `(head_index: u32, tag: u32)`. The tag increments on every
    /// push/pop to prevent ABA on the index.
    top: AtomicU64,
    /// Semaphore for async waiting when the pool is exhausted.
    semaphore: tokio::sync::Semaphore,
    buffer_size: u32,
    pool_size: usize,
}

// SAFETY: Access to `slots` is synchronized through the atomic Treiber stack.
// Each slot is exclusively owned by either the free stack (accessible only via
// atomic CAS on `top`) or by a `PooledPacket`. The semaphore ensures we never
// pop from an empty stack.
unsafe impl Send for BufferPoolInner {}
unsafe impl Sync for BufferPoolInner {}

impl BufferPoolInner {
    fn new(pool_size: usize, buffer_size: u32) -> Self {
        let slots: Box<[_]> = (0..pool_size)
            .map(|_| UnsafeCell::new(Some(vec![0u8; buffer_size as usize].into_boxed_slice())))
            .collect();

        // Build the free list: 0 -> 1 -> 2 -> ... -> EMPTY
        let next: Box<[_]> = (0..pool_size)
            .map(|i| {
                if i + 1 < pool_size {
                    AtomicU32::new((i + 1) as u32)
                } else {
                    AtomicU32::new(EMPTY)
                }
            })
            .collect();

        Self {
            slots,
            next,
            top: AtomicU64::new(pack(0, 0)),
            semaphore: tokio::sync::Semaphore::new(pool_size),
            buffer_size,
            pool_size,
        }
    }

    /// Try to pop a buffer from the free stack with a single CAS attempt.
    ///
    /// The caller **must** have acquired a semaphore permit first,
    /// guaranteeing the stack is non-empty. Returns `None` only on
    /// CAS contention (another thread popped/pushed concurrently).
    #[inline]
    fn try_pop(&self) -> Option<(u32, Box<[u8]>)> {
        let top = self.top.load(Ordering::Acquire);
        let (idx, tag) = unpack(top);
        debug_assert_ne!(idx, EMPTY, "try_pop called on empty stack");

        // Read the next pointer. This is safe because:
        // - `idx` is on the free stack, so no PooledPacket owns it
        // - The Acquire load on `top` synchronizes with the Release CAS
        //   from the push that placed `idx` at the head
        let next_idx = self.next[idx as usize].load(Ordering::Relaxed);
        let new_top = pack(next_idx, tag.wrapping_add(1));

        if self
            .top
            .compare_exchange_weak(top, new_top, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
        {
            // SAFETY: The slot is guaranteed to hold Some(buffer) when on the free stack.
            // The successful CAS gives us exclusive ownership of this slot.
            let buffer = unsafe { (*self.slots[idx as usize].get()).take().unwrap_unchecked() };
            Some((idx, buffer))
        } else {
            None
        }
    }

    /// Pop a buffer from the free stack, spinning on CAS contention.
    ///
    /// Used by the synchronous [`BufferPool::try_acquire`] path where we
    /// cannot yield to an async executor.
    #[inline]
    fn pop_sync(&self) -> (u32, Box<[u8]>) {
        loop {
            if let Some(result) = self.try_pop() {
                return result;
            }
            std::hint::spin_loop();
        }
    }

    /// Push a buffer back onto the free stack and release a semaphore permit.
    ///
    /// Called from [`PooledPacket::drop`] which is synchronous, so this must
    /// not await. CAS contention on push is extremely rare (only when multiple
    /// tasks drop packets simultaneously), so `spin_loop` is appropriate.
    #[inline]
    fn push(&self, idx: u32, buffer: Box<[u8]>) {
        // Write the buffer into the slot before making it visible on the stack.
        // SAFETY: We have exclusive ownership of this slot (it was checked out).
        unsafe {
            *self.slots[idx as usize].get() = Some(buffer);
        }

        // Push the index onto the free stack.
        loop {
            let top = self.top.load(Ordering::Relaxed);
            let (head, tag) = unpack(top);
            self.next[idx as usize].store(head, Ordering::Relaxed);
            let new_top = pack(idx, tag.wrapping_add(1));

            // Release ordering ensures the slot write above is visible
            // to any thread that subsequently pops this index.
            if self
                .top
                .compare_exchange_weak(top, new_top, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            std::hint::spin_loop();
        }

        self.semaphore.add_permits(1);
    }
}

/// A lock-free pool of reusable packet buffers.
///
/// Buffers are pre-allocated to a fixed size. When a [`PooledPacket`] is dropped,
/// its buffer is returned to the pool automatically via a single atomic CAS.
///
/// If all buffers are in use, [`BufferPool::acquire`] will await until
/// a buffer becomes available.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<BufferPoolInner>,
}

impl BufferPool {
    /// Creates a new buffer pool with `pool_size` buffers, each of `buffer_size` bytes.
    pub fn new(pool_size: usize, buffer_size: u32) -> Self {
        Self {
            inner: Arc::new(BufferPoolInner::new(pool_size, buffer_size)),
        }
    }

    /// Acquires a buffer from the pool, awaiting if none are available.
    ///
    /// If the pool is empty, awaits on the semaphore until a buffer is returned.
    /// On CAS contention (rare), yields to the tokio scheduler instead of
    /// blocking the executor thread.
    ///
    /// Returns `None` only if the semaphore has been closed (should not happen
    /// during normal operation).
    pub(crate) async fn acquire(&self) -> Option<(u32, Box<[u8]>)> {
        let permit = self.inner.semaphore.acquire().await.ok()?;
        // We manage permit count ourselves via add_permits in push.
        permit.forget();

        let mut spins = 0u32;
        loop {
            if let Some(result) = self.inner.try_pop() {
                return Some(result);
            }
            spins += 1;
            if spins < 4 {
                std::hint::spin_loop();
            } else {
                // Yield to the tokio scheduler so other tasks can make progress.
                tokio::task::yield_now().await;
                spins = 0;
            }
        }
    }

    /// Returns a buffer to the pool by slot index.
    ///
    /// Used by the reader on error paths to avoid leaking pool buffers.
    pub(crate) fn return_buffer(&self, slot_index: u32, buffer: Box<[u8]>) {
        self.inner.push(slot_index, buffer);
    }

    /// Creates a [`PooledPacket`] that will return its buffer to this pool on drop.
    pub(crate) fn create_packet(
        &self,
        header: PacketHeader,
        data_len: usize,
        slot_index: u32,
        buffer: Box<[u8]>,
    ) -> PooledPacket {
        PooledPacket {
            header,
            data_len,
            buffer: ManuallyDrop::new(buffer),
            pool: Arc::clone(&self.inner),
            slot_index,
        }
    }

    /// Returns the buffer size of buffers in this pool.
    pub fn buffer_size(&self) -> u32 {
        self.inner.buffer_size
    }

    /// Returns the total number of buffers in this pool.
    pub fn pool_size(&self) -> usize {
        self.inner.pool_size
    }

    /// Tries to acquire a buffer without awaiting.
    ///
    /// Returns `None` if no buffers are currently available.
    pub fn try_acquire(&self) -> Option<(u32, Box<[u8]>)> {
        let permit = self.inner.semaphore.try_acquire().ok()?;
        permit.forget();
        Some(self.inner.pop_sync())
    }
}

impl std::fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BufferPool")
            .field("buffer_size", &self.inner.buffer_size)
            .field("pool_size", &self.inner.pool_size)
            .finish()
    }
}

/// An owned packet read from a pcap file using a pooled buffer.
///
/// Contains both the parsed [`PacketHeader`] and the packet data in a
/// pooled buffer. When dropped, the buffer is automatically returned
/// to the [`BufferPool`] via a single atomic CAS operation.
///
/// This type is `Send + Sync` and can be sent through channels.
///
/// Access packet data via [`data()`](PooledPacket::data) or the
/// [`Deref<Target=[u8]>`](std::ops::Deref) implementation.
pub struct PooledPacket {
    header: PacketHeader,
    data_len: usize,
    buffer: ManuallyDrop<Box<[u8]>>,
    pool: Arc<BufferPoolInner>,
    slot_index: u32,
}

impl PooledPacket {
    /// Returns the packet header.
    pub fn header(&self) -> &PacketHeader {
        &self.header
    }

    /// Returns the packet data as a byte slice.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buffer[..self.data_len]
    }
}

impl std::ops::Deref for PooledPacket {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.data()
    }
}

impl Drop for PooledPacket {
    fn drop(&mut self) {
        // SAFETY: The buffer is always valid from construction until this Drop call.
        // ManuallyDrop::take is called exactly once here, and no other code takes the buffer.
        let buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
        self.pool.push(self.slot_index, buffer);
    }
}

impl std::fmt::Debug for PooledPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledPacket")
            .field("header", &self.header)
            .field("data_len", &self.data_len)
            .finish()
    }
}

// SAFETY: All fields are Send + Sync:
// - PacketHeader is Copy
// - ManuallyDrop<Box<[u8]>> is Send + Sync
// - Arc<BufferPoolInner> is Send + Sync (we impl'd Send+Sync for BufferPoolInner)
// - u32 and usize are Send + Sync
unsafe impl Send for PooledPacket {}
unsafe impl Sync for PooledPacket {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::packet_header::PacketTimestamp;

    fn dummy_header() -> PacketHeader {
        PacketHeader {
            timestamp: PacketTimestamp { seconds: 0, usec: 0 },
            include_len: 10,
            orig_len: 10,
        }
    }

    #[tokio::test]
    async fn acquire_and_return() {
        let pool = BufferPool::new(4, 128);
        assert_eq!(pool.pool_size(), 4);
        assert_eq!(pool.buffer_size(), 128);

        // Acquire all 4 buffers
        let (idx0, buf0) = pool.acquire().await.expect("acquire 0");
        let (idx1, buf1) = pool.acquire().await.expect("acquire 1");
        let (idx2, buf2) = pool.acquire().await.expect("acquire 2");
        let (idx3, buf3) = pool.acquire().await.expect("acquire 3");

        // All indices should be unique
        let indices = [idx0, idx1, idx2, idx3];
        for i in 0..indices.len() {
            for j in (i + 1)..indices.len() {
                assert_ne!(indices[i], indices[j], "indices must be unique");
            }
        }

        // All buffers should be the right size
        assert_eq!(buf0.len(), 128);
        assert_eq!(buf1.len(), 128);
        assert_eq!(buf2.len(), 128);
        assert_eq!(buf3.len(), 128);

        // Return one and acquire again
        pool.return_buffer(idx1, buf1);
        let (idx_reused, buf_reused) = pool.acquire().await.expect("acquire reused");
        assert_eq!(idx_reused, idx1);
        assert_eq!(buf_reused.len(), 128);

        // Clean up
        pool.return_buffer(idx0, buf0);
        pool.return_buffer(idx2, buf2);
        pool.return_buffer(idx3, buf3);
        pool.return_buffer(idx_reused, buf_reused);
    }

    #[tokio::test]
    async fn pool_waits_when_empty() {
        let pool = BufferPool::new(1, 64);

        // Acquire the only buffer
        let (idx, buf) = pool.acquire().await.expect("acquire");

        // Spawn a task that tries to acquire — it should block
        let pool_clone = pool.clone();
        let handle = tokio::spawn(async move {
            let (idx, buf) = pool_clone.acquire().await.expect("acquire from waiter");
            (idx, buf.len())
        });

        // Give the spawned task a chance to start waiting
        tokio::task::yield_now().await;

        // The task should not have completed yet
        assert!(!handle.is_finished());

        // Return the buffer — the waiting task should now complete
        pool.return_buffer(idx, buf);
        let (returned_idx, len) = handle.await.expect("task panicked");
        assert_eq!(returned_idx, idx);
        assert_eq!(len, 64);
    }

    #[tokio::test]
    async fn pooled_packet_returns_buffer_on_drop() {
        let pool = BufferPool::new(1, 64);

        let (idx, mut buf) = pool.acquire().await.expect("acquire");
        buf[..5].copy_from_slice(b"hello");

        let packet = pool.create_packet(dummy_header(), 5, idx, buf);
        assert_eq!(packet.data(), b"hello");
        assert_eq!(packet.header().include_len, 10);

        // Drop the packet — buffer should return to pool
        drop(packet);

        // Should be able to acquire again immediately
        let (idx2, _buf2) = pool.acquire().await.expect("acquire after drop");
        // Got the same slot back
        assert_eq!(idx2, idx);

        pool.return_buffer(idx2, _buf2);
    }

    #[tokio::test]
    async fn pooled_packet_deref() {
        let pool = BufferPool::new(1, 32);
        let (idx, mut buf) = pool.acquire().await.expect("acquire");
        buf[..3].copy_from_slice(&[1, 2, 3]);

        let packet = pool.create_packet(dummy_header(), 3, idx, buf);

        // Test Deref
        let slice: &[u8] = &*packet;
        assert_eq!(slice, &[1, 2, 3]);
        assert_eq!(packet.len(), 3);
    }

    #[tokio::test]
    async fn concurrent_acquire_release() {
        let pool = BufferPool::new(4, 64);
        let mut handles = Vec::new();

        for _ in 0..8 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..100 {
                    let (idx, buf) = pool.acquire().await.expect("acquire");
                    // Simulate some work
                    tokio::task::yield_now().await;
                    pool.return_buffer(idx, buf);
                }
            }));
        }

        for handle in handles {
            handle.await.expect("task panicked");
        }

        // All buffers should be back in the pool
        let mut acquired = Vec::new();
        for _ in 0..4 {
            acquired.push(pool.acquire().await.expect("acquire final"));
        }
        assert_eq!(acquired.len(), 4);

        for (idx, buf) in acquired {
            pool.return_buffer(idx, buf);
        }
    }

    #[tokio::test]
    async fn send_pooled_packet_through_channel() {
        let pool = BufferPool::new(2, 64);
        let (tx, mut rx) = tokio::sync::mpsc::channel::<PooledPacket>(4);

        let pool_clone = pool.clone();
        let producer = tokio::spawn(async move {
            for i in 0u8..10 {
                let (idx, mut buf) = pool_clone.acquire().await.expect("acquire");
                buf[0] = i;
                let packet = pool_clone.create_packet(dummy_header(), 1, idx, buf);
                tx.send(packet).await.expect("send");
            }
        });

        let mut received = Vec::new();
        while let Some(packet) = rx.recv().await {
            received.push(packet.data()[0]);
            // Dropping packet here returns buffer to pool
        }

        producer.await.expect("producer panicked");
        assert_eq!(received, (0..10).collect::<Vec<u8>>());
    }

    #[tokio::test]
    async fn packet_data_write_then_read() {
        let pool = BufferPool::new(1, 256);
        let (idx, mut buf) = pool.acquire().await.expect("acquire");

        let data = b"packet payload data";
        buf[..data.len()].copy_from_slice(data);

        let packet = pool.create_packet(dummy_header(), data.len(), idx, buf);
        assert_eq!(packet.data(), data);

        // Verify header access
        assert_eq!(packet.header().include_len, 10);
        assert_eq!(packet.header().orig_len, 10);
    }

    #[test]
    fn debug_impls() {
        let pool = BufferPool::new(2, 128);
        let debug = format!("{:?}", pool);
        assert!(debug.contains("BufferPool"));
        assert!(debug.contains("128"));
        assert!(debug.contains("2"));
    }

    #[test]
    fn pack_unpack_roundtrip() {
        assert_eq!(unpack(pack(0, 0)), (0, 0));
        assert_eq!(unpack(pack(42, 99)), (42, 99));
        assert_eq!(unpack(pack(EMPTY, u32::MAX)), (EMPTY, u32::MAX));
        assert_eq!(unpack(pack(0, u32::MAX)), (0, u32::MAX));
        assert_eq!(unpack(pack(u32::MAX, 0)), (u32::MAX, 0));
    }

    // ---- Miri-compatible tests (no tokio, use try_acquire + std::thread) ----

    #[test]
    fn miri_try_acquire_and_return() {
        let pool = BufferPool::new(3, 64);

        let (idx0, buf0) = pool.try_acquire().expect("acquire 0");
        let (idx1, buf1) = pool.try_acquire().expect("acquire 1");
        let (idx2, buf2) = pool.try_acquire().expect("acquire 2");

        // Pool should be empty now
        assert!(pool.try_acquire().is_none());

        // Return one
        pool.return_buffer(idx1, buf1);

        // Should be available again
        let (idx_reused, buf_reused) = pool.try_acquire().expect("acquire reused");
        assert_eq!(idx_reused, idx1);

        // Still empty
        assert!(pool.try_acquire().is_none());

        pool.return_buffer(idx0, buf0);
        pool.return_buffer(idx2, buf2);
        pool.return_buffer(idx_reused, buf_reused);
    }

    #[test]
    fn miri_pooled_packet_drop_returns_buffer() {
        let pool = BufferPool::new(1, 32);

        let (idx, mut buf) = pool.try_acquire().expect("acquire");
        buf[..3].copy_from_slice(&[10, 20, 30]);

        assert!(pool.try_acquire().is_none(), "pool should be empty");

        let packet = pool.create_packet(dummy_header(), 3, idx, buf);
        assert_eq!(packet.data(), &[10, 20, 30]);
        assert_eq!(packet.header().include_len, 10);

        drop(packet);

        // Buffer should be back in the pool
        let (idx2, buf2) = pool.try_acquire().expect("acquire after drop");
        assert_eq!(idx2, idx);
        pool.return_buffer(idx2, buf2);
    }

    #[test]
    fn miri_pooled_packet_deref() {
        let pool = BufferPool::new(1, 16);
        let (idx, mut buf) = pool.try_acquire().expect("acquire");
        buf[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let packet = pool.create_packet(dummy_header(), 4, idx, buf);
        let slice: &[u8] = &*packet;
        assert_eq!(slice, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn miri_concurrent_threads() {
        use std::sync::Barrier;

        let pool = BufferPool::new(4, 64);
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();

        for _ in 0..4 {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..50 {
                    // Spin until we get a buffer (since try_acquire may fail under contention)
                    let (idx, buf) = loop {
                        if let Some(acquired) = pool.try_acquire() {
                            break acquired;
                        }
                        std::thread::yield_now();
                    };
                    // Verify buffer is valid
                    assert_eq!(buf.len(), 64);
                    pool.return_buffer(idx, buf);
                }
            }));
        }

        for handle in handles {
            handle.join().expect("thread panicked");
        }

        // All 4 buffers should be back
        for _ in 0..4 {
            assert!(pool.try_acquire().is_some());
        }
        assert!(pool.try_acquire().is_none());
    }

    #[test]
    fn miri_multiple_packets_lifecycle() {
        let pool = BufferPool::new(3, 128);

        // Create 3 packets
        let mut packets = Vec::new();
        for i in 0u8..3 {
            let (idx, mut buf) = pool.try_acquire().expect("acquire");
            buf[0] = i;
            packets.push(pool.create_packet(dummy_header(), 1, idx, buf));
        }

        assert!(pool.try_acquire().is_none());

        // Verify data
        for (i, packet) in packets.iter().enumerate() {
            assert_eq!(packet.data()[0], i as u8);
        }

        // Drop one at a time, verify pool refills
        let _ = packets.pop();
        let (idx, buf) = pool.try_acquire().expect("should have 1 free");
        pool.return_buffer(idx, buf);

        drop(packets);
        // All 3 should be free now
        for _ in 0..3 {
            assert!(pool.try_acquire().is_some());
        }
    }
}
