//! Buffer pool for audio frames
//!
//! Reduces allocations in hot audio path by reusing Vec<u8> buffers.
//! Thread-safe using parking_lot::Mutex for lock-free fast path.

use parking_lot::Mutex;
use std::sync::Arc;

/// Default buffer size for 20ms @ 8kHz stereo (worst case)
const DEFAULT_BUFFER_SIZE: usize = 640;

/// Maximum number of buffers to keep in pool
const MAX_POOL_SIZE: usize = 32;

/// A reusable buffer from the pool
#[derive(Debug)]
pub struct PooledBuffer {
    /// The actual buffer data
    data: Vec<u8>,
    /// Reference to the pool for returning the buffer
    pool: Arc<BufferPool>,
}

impl PooledBuffer {
    /// Get the buffer as a mutable slice
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Get the buffer as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Resize the buffer (for variable-length reads)
    pub fn resize(&mut self, new_len: usize) {
        self.data.resize(new_len, 0);
    }

    /// Truncate to actual data length
    pub fn truncate(&mut self, len: usize) {
        self.data.truncate(len);
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Take ownership of the data (consumes the pooled buffer without returning to pool)
    pub fn into_vec(mut self) -> Vec<u8> {
        // Take the data - this leaves self.data with capacity 0
        // so Drop won't return it to the pool
        std::mem::take(&mut self.data)
    }

    /// Clone the data to a new Vec (keeps buffer in pool)
    pub fn to_vec(&self) -> Vec<u8> {
        self.data.clone()
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        // Return buffer to pool if it still has capacity (wasn't consumed by into_vec)
        if self.data.capacity() > 0 {
            let mut data = std::mem::take(&mut self.data);
            // Clear but keep capacity
            data.clear();
            self.pool.return_buffer(data);
        }
    }
}

/// Thread-safe buffer pool
#[derive(Debug)]
pub struct BufferPool {
    /// Pool of available buffers
    buffers: Mutex<Vec<Vec<u8>>>,
    /// Default buffer capacity
    buffer_size: usize,
}

impl BufferPool {
    /// Create a new buffer pool
    pub fn new() -> Arc<Self> {
        Self::with_capacity(DEFAULT_BUFFER_SIZE)
    }

    /// Create a buffer pool with specified default buffer size
    pub fn with_capacity(buffer_size: usize) -> Arc<Self> {
        Arc::new(Self {
            buffers: Mutex::new(Vec::with_capacity(MAX_POOL_SIZE)),
            buffer_size,
        })
    }

    /// Get a buffer from the pool (or allocate a new one)
    pub fn get(self: &Arc<Self>) -> PooledBuffer {
        let data = {
            let mut pool = self.buffers.lock();
            pool.pop()
        }.unwrap_or_else(|| Vec::with_capacity(self.buffer_size));

        PooledBuffer {
            data,
            pool: Arc::clone(self),
        }
    }

    /// Get a buffer with minimum size
    pub fn get_with_size(self: &Arc<Self>, min_size: usize) -> PooledBuffer {
        let mut buffer = self.get();
        if buffer.data.capacity() < min_size {
            buffer.data.reserve(min_size - buffer.data.capacity());
        }
        buffer.data.resize(min_size, 0);
        buffer
    }

    /// Return a buffer to the pool
    fn return_buffer(&self, buffer: Vec<u8>) {
        let mut pool = self.buffers.lock();
        if pool.len() < MAX_POOL_SIZE {
            pool.push(buffer);
        }
        // If pool is full, buffer is dropped (freed)
    }

    /// Get current pool size (for stats/debugging)
    pub fn available(&self) -> usize {
        self.buffers.lock().len()
    }

    /// Pre-allocate buffers
    pub fn preallocate(&self, count: usize) {
        let mut pool = self.buffers.lock();
        let to_add = count.min(MAX_POOL_SIZE).saturating_sub(pool.len());
        for _ in 0..to_add {
            pool.push(Vec::with_capacity(self.buffer_size));
        }
    }
}

impl Default for BufferPool {
    fn default() -> Self {
        Self {
            buffers: Mutex::new(Vec::with_capacity(MAX_POOL_SIZE)),
            buffer_size: DEFAULT_BUFFER_SIZE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pool_basic() {
        let pool = BufferPool::new();

        // Get a buffer
        let mut buf = pool.get();
        assert_eq!(pool.available(), 0);

        // Use the buffer
        buf.resize(100);
        buf.as_mut_slice()[0] = 42;

        // Drop returns to pool
        drop(buf);
        assert_eq!(pool.available(), 1);

        // Get again - should reuse
        let buf2 = pool.get();
        assert!(buf2.data.capacity() >= DEFAULT_BUFFER_SIZE);
        drop(buf2);
    }

    #[test]
    fn test_pool_into_vec() {
        let pool = BufferPool::new();

        let mut buf = pool.get_with_size(100);
        buf.as_mut_slice()[0] = 42;

        // into_vec consumes without returning to pool
        let vec = buf.into_vec();
        assert_eq!(vec.len(), 100);
        assert_eq!(vec[0], 42);
        assert_eq!(pool.available(), 0);
    }

    #[test]
    fn test_pool_max_size() {
        let pool = BufferPool::new();

        // Get more than MAX_POOL_SIZE buffers
        let buffers: Vec<_> = (0..MAX_POOL_SIZE + 10)
            .map(|_| pool.get())
            .collect();

        // Return all
        drop(buffers);

        // Pool should be capped at MAX_POOL_SIZE
        assert_eq!(pool.available(), MAX_POOL_SIZE);
    }

    #[test]
    fn test_preallocate() {
        let pool = BufferPool::new();
        pool.preallocate(10);
        assert_eq!(pool.available(), 10);
    }
}
