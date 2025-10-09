use libsodium_sys::ffi;

use crate::Sodium;

/// Set of functions to generate unpredictable data, suitable for creating secret keys
pub trait RandomBytes {
    /// Returns an unpredictable value between 0 and 0xffffffff (included).
    fn randombytes_random(&self) -> u32;

    /// Returns an unpredictable value between 0 and 'upper_bound' (excluded).
    /// Unlike [`randombytes_random()`](Self::randombytes_random()) % upper_bound, it guarantees a uniform distribution of the possible output values
    /// even when upper_bound is not a power of 2.
    fn randombytes_uniform(&self, upper_bound: u32) -> u32;

    /// Fills `size` bytes into `buf` with an unpredictable sequence of bytes
    fn randombytes_buf(&self, buf: &mut [u8], size: usize) -> Result<(), &str>;
}

impl RandomBytes for Sodium {
    fn randombytes_random(&self) -> u32 {
        unsafe { ffi::randombytes_random() }
    }

    fn randombytes_uniform(&self, upper_bound: u32) -> u32 {
        unsafe { ffi::randombytes_uniform(upper_bound) }
    }

    fn randombytes_buf(&self, buf: &mut [u8], size: usize) -> Result<(), &str> {
        if size > buf.len() {
            return Err("Size exceeds buf capacity");
        }

        unsafe {
            ffi::randombytes_buf(buf.as_mut_ptr() as _, size);
        }

        Ok(())
    }
}
