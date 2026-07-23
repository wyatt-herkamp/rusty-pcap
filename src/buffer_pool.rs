//! Lock-free buffer pool for async pcap/pcap-ng reading with owned packet buffers.
//!
//! Shared by the pooled readers of both file formats
//! ([`AsyncPooledPcapReader`](crate::pcap::AsyncPooledPcapReader) and
//! [`AsyncPooledPcapNgReader`](crate::pcap_ng::AsyncPooledPcapNgReader)).
//!
//! Uses a Treiber stack (lock-free atomic stack) for O(1) buffer acquire/release
//! and a [`tokio::sync::Notify`] for async waiting when the pool is empty. The
//! hot paths — acquiring while buffers are free and releasing while no one is
//! waiting — are a single CAS each, with no locks.
#![allow(unsafe_code)]

use std::cell::UnsafeCell;
use std::mem::ManuallyDrop;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use tokio::sync::Notify;

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
    /// Wakes tasks waiting in [`BufferPool::acquire`] when the pool is exhausted.
    /// When no task is waiting (the common case), notifying is a single atomic op.
    notify: Notify,
    buffer_size: u32,
    pool_size: usize,
}

// SAFETY: Access to `slots` is synchronized through the atomic Treiber stack.
// Each slot is exclusively owned by either the free stack (accessible only via
// atomic CAS on `top`) or by a `PooledPacket`. `try_pop` checks for the `EMPTY`
// sentinel, so a slot is only accessed after a successful CAS grants ownership.
unsafe impl Send for BufferPoolInner {}
unsafe impl Sync for BufferPoolInner {}

impl BufferPoolInner {
    /// Creates a new buffer pool with the given number of buffers and buffer size.
    fn new(pool_size: NonZeroUsize, buffer_size: u32) -> Self {
        let pool_size = pool_size.get();
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
            notify: Notify::new(),
            buffer_size,
            pool_size,
        }
    }

    /// Pop a buffer from the free stack, spinning on CAS contention.
    ///
    /// Returns `None` only when the stack is empty.
    #[inline]
    fn try_pop(&self) -> Option<(u32, Box<[u8]>)> {
        loop {
            let top = self.top.load(Ordering::Acquire);
            let (idx, tag) = unpack(top);
            if idx == EMPTY {
                return None;
            }

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
                return Some((idx, buffer));
            }
            std::hint::spin_loop();
        }
    }

    /// Push a buffer back onto the free stack and wake one waiter, if any.
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

        // Wake a waiter if one is registered. When no task is waiting this is a
        // single atomic operation; the stored permit also covers the race where a
        // waiter registers between our push above and this call.
        self.notify.notify_one();
    }

    /// Push a pre-linked chain of slots (`head` -> ... -> `tail` via `next`) onto
    /// the free stack with a single CAS, then wake one waiter.
    ///
    /// The caller must have exclusive ownership of every slot in the chain and
    /// must have already stored the buffers into their slots.
    fn push_chain(&self, head: u32, tail: u32) {
        loop {
            let top = self.top.load(Ordering::Relaxed);
            let (old_head, tag) = unpack(top);
            self.next[tail as usize].store(old_head, Ordering::Relaxed);
            let new_top = pack(head, tag.wrapping_add(1));

            // Release ordering publishes the slot and chain writes to any thread
            // that subsequently pops these indices.
            if self
                .top
                .compare_exchange_weak(top, new_top, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                break;
            }
            std::hint::spin_loop();
        }

        self.notify.notify_one();
    }
}

/// A lock-free pool of reusable packet buffers.
///
/// Buffers are pre-allocated to a fixed size. When a [`PooledPacket`] is dropped,
/// its buffer is returned to the pool automatically via a single atomic CAS.
///
/// If all buffers are in use, acquiring a new one will await until a buffer
/// becomes available.
#[derive(Clone)]
pub struct BufferPool {
    inner: Arc<BufferPoolInner>,
}

impl BufferPool {
    /// Creates a new buffer pool with `pool_size` buffers, each of `buffer_size` bytes.
    pub fn new(pool_size: NonZeroUsize, buffer_size: u32) -> Self {
        Self {
            inner: Arc::new(BufferPoolInner::new(pool_size, buffer_size)),
        }
    }

    /// Acquires a buffer from the pool, awaiting if none are available.
    ///
    /// While buffers are free this is a single CAS with no locks or wakeups.
    /// If the pool is empty, awaits until a buffer is returned.
    ///
    /// Always returns `Some`; the `Option` is kept for API stability.
    pub(crate) async fn acquire(&self) -> Option<(u32, Box<[u8]>)> {
        if let Some(result) = self.inner.try_pop() {
            return Some(result);
        }
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            // Register interest before re-checking so a push between the failed
            // pop above and the await below cannot be missed.
            notified.as_mut().enable();
            if let Some(result) = self.inner.try_pop() {
                return Some(result);
            }
            notified.await;
            if let Some(result) = self.inner.try_pop() {
                // A chain return ([BufferPool::recycle]) frees many buffers with a
                // single wakeup; pass the wakeup along while buffers remain so
                // other waiters are not stranded.
                if unpack(self.inner.top.load(Ordering::Relaxed)).0 != EMPTY {
                    self.inner.notify.notify_one();
                }
                return Some(result);
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
    pub(crate) fn create_packet<H>(
        &self,
        header: H,
        data_len: usize,
        slot_index: u32,
        buffer: Box<[u8]>,
    ) -> PooledPacket<H> {
        PooledPacket {
            header,
            data_len,
            buffer: ManuallyDrop::new(buffer),
            pool: ManuallyDrop::new(Arc::clone(&self.inner)),
            slot_index,
        }
    }

    /// Returns a batch of packets to the pool with a single atomic splice.
    ///
    /// Dropping packets one at a time costs one CAS on the shared stack head (plus
    /// one waiter wakeup) per packet, which turns into cross-core cache-line
    /// bouncing when the consumer runs on a different thread than the reader. This
    /// links the returned buffers into a local chain and pushes the whole chain
    /// with one CAS and one wakeup.
    ///
    /// Packets created by a different pool are returned to their own pool
    /// individually.
    pub fn recycle<H>(&self, packets: impl IntoIterator<Item = PooledPacket<H>>) {
        let mut chain_head = EMPTY;
        let mut chain_tail = EMPTY;
        for mut packet in packets {
            // SAFETY: Both ManuallyDrop fields are taken exactly once here and the
            // packet is forgotten immediately after, so Drop never runs on it.
            let buffer = unsafe { ManuallyDrop::take(&mut packet.buffer) };
            let pool = unsafe { ManuallyDrop::take(&mut packet.pool) };
            let idx = packet.slot_index;
            std::mem::forget(packet);

            if !Arc::ptr_eq(&pool, &self.inner) {
                pool.push(idx, buffer);
                continue;
            }

            // SAFETY: We have exclusive ownership of this slot (it was checked out
            // by the packet we just disassembled).
            unsafe {
                *self.inner.slots[idx as usize].get() = Some(buffer);
            }
            if chain_head == EMPTY {
                chain_tail = idx;
            }
            self.inner.next[idx as usize].store(chain_head, Ordering::Relaxed);
            chain_head = idx;
        }
        if chain_head != EMPTY {
            self.inner.push_chain(chain_head, chain_tail);
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
        self.inner.try_pop()
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
///
/// The header type `H` defaults to [`PacketHeader`] for classic pcap. Other
/// readers (e.g. the pcap-ng pooled reader) instantiate it with their own owned
/// header type such as [`AnyPacketHeader`](crate::any_reader::AnyPacketHeader).
pub struct PooledPacket<H = PacketHeader> {
    header: H,
    data_len: usize,
    buffer: ManuallyDrop<Box<[u8]>>,
    pool: ManuallyDrop<Arc<BufferPoolInner>>,
    slot_index: u32,
}
impl<H> AsRef<H> for PooledPacket<H> {
    fn as_ref(&self) -> &H {
        &self.header
    }
}

impl<H> PooledPacket<H> {
    /// Returns the packet header.
    pub fn header(&self) -> &H {
        &self.header
    }

    /// Returns the packet data as a byte slice.
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.buffer[..self.data_len]
    }
}

impl<H> std::ops::Deref for PooledPacket<H> {
    type Target = [u8];

    #[inline]
    fn deref(&self) -> &[u8] {
        self.data()
    }
}

impl<H> Drop for PooledPacket<H> {
    fn drop(&mut self) {
        // SAFETY: Both fields are valid from construction until this Drop call.
        // ManuallyDrop::take is called exactly once for each; the only other code
        // that takes them ([BufferPool::recycle]) forgets the packet, so Drop
        // never runs afterwards.
        let buffer = unsafe { ManuallyDrop::take(&mut self.buffer) };
        let pool = unsafe { ManuallyDrop::take(&mut self.pool) };
        pool.push(self.slot_index, buffer);
    }
}

impl<H: std::fmt::Debug> std::fmt::Debug for PooledPacket<H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PooledPacket")
            .field("header", &self.header)
            .field("data_len", &self.data_len)
            .finish()
    }
}

// SAFETY: All non-header fields are Send + Sync:
// - ManuallyDrop<Box<[u8]>> is Send + Sync
// - Arc<BufferPoolInner> is Send + Sync (we impl'd Send+Sync for BufferPoolInner)
// - u32 and usize are Send + Sync
// The header `H` gates the impls: a packet is Send only when its header is Send,
// and likewise for Sync.
unsafe impl<H: Send> Send for PooledPacket<H> {}
unsafe impl<H: Sync> Sync for PooledPacket<H> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pcap::packet_header::PacketTimestamp;

    fn dummy_header() -> PacketHeader {
        PacketHeader {
            timestamp: PacketTimestamp {
                seconds: 0,
                usec: 0,
            },
            include_len: 10,
            orig_len: 10,
        }
    }

    #[tokio::test]
    async fn acquire_and_return() {
        let pool = BufferPool::new(NonZeroUsize::new(4).unwrap(), 128);
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
        let pool = BufferPool::new(NonZeroUsize::new(1).unwrap(), 64);

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
        let pool = BufferPool::new(NonZeroUsize::new(1).unwrap(), 64);

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
        let pool = BufferPool::new(NonZeroUsize::new(1).unwrap(), 32);
        let (idx, mut buf) = pool.acquire().await.expect("acquire");
        buf[..3].copy_from_slice(&[1, 2, 3]);

        let packet = pool.create_packet(dummy_header(), 3, idx, buf);

        // Test Deref
        let slice: &[u8] = &packet;
        assert_eq!(slice, &[1, 2, 3]);
        assert_eq!(packet.len(), 3);
    }

    #[tokio::test]
    async fn concurrent_acquire_release() {
        let pool = BufferPool::new(NonZeroUsize::new(4).unwrap(), 64);
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
        let pool = BufferPool::new(NonZeroUsize::new(2).unwrap(), 64);
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
        let pool = BufferPool::new(NonZeroUsize::new(1).unwrap(), 256);
        let (idx, mut buf) = pool.acquire().await.expect("acquire");

        let data = b"packet payload data";
        buf[..data.len()].copy_from_slice(data);

        let packet = pool.create_packet(dummy_header(), data.len(), idx, buf);
        assert_eq!(packet.data(), data);

        // Verify header access
        assert_eq!(packet.header().include_len, 10);
        assert_eq!(packet.header().orig_len, 10);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn recycle_wakes_all_waiters() {
        // Exhaust the pool, park several waiters, then return everything with a
        // single recycle() (which issues a single notify_one). The wakeup
        // forwarding in acquire() must chain-wake every waiter; a lost wakeup
        // hangs this test.
        for _ in 0..200 {
            let pool = BufferPool::new(NonZeroUsize::new(4).unwrap(), 32);
            let mut packets = Vec::new();
            for _ in 0..4 {
                let (idx, buf) = pool.acquire().await.expect("acquire");
                packets.push(pool.create_packet(dummy_header(), 0, idx, buf));
            }
            let mut waiters = Vec::new();
            for _ in 0..4 {
                let pool = pool.clone();
                waiters.push(tokio::spawn(async move {
                    let (idx, buf) = pool.acquire().await.expect("acquire from waiter");
                    // Hold briefly so waiters overlap, then return.
                    tokio::task::yield_now().await;
                    pool.return_buffer(idx, buf);
                }));
            }
            tokio::task::yield_now().await;
            pool.recycle(packets);
            let all = async {
                for waiter in waiters {
                    waiter.await.expect("waiter panicked");
                }
            };
            tokio::time::timeout(std::time::Duration::from_secs(5), all)
                .await
                .expect("lost wakeup: waiters hung after recycle");
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 8)]
    async fn mixed_drop_and_recycle_contention() {
        // Mixed individual drops + batch recycles under heavy contention.
        let pool = BufferPool::new(NonZeroUsize::new(4).unwrap(), 32);
        let mut handles = Vec::new();
        for t in 0..16 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                for i in 0..500 {
                    let (idx, buf) = pool.acquire().await.expect("acquire");
                    let packet = pool.create_packet(dummy_header(), 0, idx, buf);
                    if (t + i) % 3 == 0 {
                        pool.recycle([packet]);
                    } else {
                        drop(packet);
                    }
                }
            }));
        }
        let all = async {
            for handle in handles {
                handle.await.expect("task panicked");
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(30), all)
            .await
            .expect("hung: lost wakeup or stack corruption");
        for _ in 0..4 {
            assert!(pool.try_acquire().is_some());
        }
        assert!(pool.try_acquire().is_none());
    }

    #[test]
    fn debug_impls() {
        let pool = BufferPool::new(NonZeroUsize::new(2).unwrap(), 128);
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
        let pool = BufferPool::new(NonZeroUsize::new(3).unwrap(), 64);

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
        let pool = BufferPool::new(NonZeroUsize::new(1).unwrap(), 32);

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
        let pool = BufferPool::new(NonZeroUsize::new(1).unwrap(), 16);
        let (idx, mut buf) = pool.try_acquire().expect("acquire");
        buf[..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let packet = pool.create_packet(dummy_header(), 4, idx, buf);
        let slice: &[u8] = &packet;
        assert_eq!(slice, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn miri_concurrent_threads() {
        use std::sync::Barrier;

        let pool = BufferPool::new(NonZeroUsize::new(4).unwrap(), 64);
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
    fn miri_recycle_returns_all_buffers() {
        let pool = BufferPool::new(NonZeroUsize::new(4).unwrap(), 64);
        let mut packets = Vec::new();
        for i in 0u8..4 {
            let (idx, mut buf) = pool.try_acquire().expect("acquire");
            buf[0] = i;
            packets.push(pool.create_packet(dummy_header(), 1, idx, buf));
        }
        assert!(pool.try_acquire().is_none());

        pool.recycle(packets);

        // All 4 buffers must be back, with unique indices, and slots intact.
        let mut seen = Vec::new();
        let mut held = Vec::new();
        for _ in 0..4 {
            let (idx, buf) = pool.try_acquire().expect("buffer back after recycle");
            assert_eq!(buf.len(), 64);
            assert!(!seen.contains(&idx), "duplicate slot index after recycle");
            seen.push(idx);
            held.push((idx, buf));
        }
        assert!(pool.try_acquire().is_none());
        for (idx, buf) in held {
            pool.return_buffer(idx, buf);
        }
    }

    #[test]
    fn miri_recycle_empty_and_single() {
        let pool = BufferPool::new(NonZeroUsize::new(2).unwrap(), 32);
        pool.recycle(Vec::<PooledPacket>::new()); // empty iterator: no-op, must not corrupt stack
        let (idx, buf) = pool.try_acquire().expect("acquire");
        let packet = pool.create_packet(dummy_header(), 0, idx, buf);
        pool.recycle([packet]); // single-element chain: head == tail
        assert!(pool.try_acquire().is_some());
        assert!(pool.try_acquire().is_some());
        assert!(pool.try_acquire().is_none());
    }

    #[test]
    fn miri_recycle_cross_pool() {
        let pool_a = BufferPool::new(NonZeroUsize::new(1).unwrap(), 32);
        let pool_b = BufferPool::new(NonZeroUsize::new(1).unwrap(), 32);
        let (idx_a, buf_a) = pool_a.try_acquire().expect("acquire a");
        let (idx_b, buf_b) = pool_b.try_acquire().expect("acquire b");
        let packet_a = pool_a.create_packet(dummy_header(), 0, idx_a, buf_a);
        let packet_b = pool_b.create_packet(dummy_header(), 0, idx_b, buf_b);
        // Recycle both through pool_a: packet_b must land back in pool_b.
        pool_a.recycle([packet_a, packet_b]);
        assert!(pool_a.try_acquire().is_some());
        assert!(pool_b.try_acquire().is_some());
    }

    #[test]
    fn miri_recycle_concurrent_threads() {
        use std::sync::Barrier;

        let pool = BufferPool::new(NonZeroUsize::new(8).unwrap(), 32);
        let barrier = Arc::new(Barrier::new(4));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let pool = pool.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for _ in 0..25 {
                    let mut batch = Vec::new();
                    for _ in 0..2 {
                        let (idx, buf) = loop {
                            if let Some(acquired) = pool.try_acquire() {
                                break acquired;
                            }
                            std::thread::yield_now();
                        };
                        batch.push(pool.create_packet(dummy_header(), 0, idx, buf));
                    }
                    pool.recycle(batch);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread panicked");
        }
        for _ in 0..8 {
            assert!(pool.try_acquire().is_some());
        }
        assert!(pool.try_acquire().is_none());
    }

    #[test]
    fn miri_multiple_packets_lifecycle() {
        let pool = BufferPool::new(NonZeroUsize::new(3).unwrap(), 128);

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
