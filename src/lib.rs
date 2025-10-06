use std::mem::MaybeUninit;

use libsodium_sys::ffi;

/// The minimum recommended output size
pub const BYTES: usize = ffi::crypto_generichash_BYTES as usize;
/// The recommended key size
pub const KEYBYTES: usize = ffi::crypto_generichash_KEYBYTES as usize;

/// Sodium library object
#[non_exhaustive] // forces user to use constructor (ie. `new` method)
pub struct Sodium;

impl Sodium {
    /// Creates initialized Sodium struct
    pub fn new() -> Result<Self, i32> {
        let e = unsafe { ffi::sodium_init() };
        if e < 0 {
            Err(e)
        } else {
            Ok(Self)
        }
    }

    /// Creates a key of the recommended length [`KEYBYTES`]
    pub fn crypto_generichash_keygen(&self) -> Vec<u8> {
        let mut buf = MaybeUninit::<[u8; KEYBYTES]>::uninit();

        unsafe { ffi::crypto_generichash_keygen(buf.as_mut_ptr() as *mut u8) };
        unsafe { buf.assume_init() }.to_vec()
    }

    /// Returns a fingerprint of the message `input`. The output size can be chosen by the application (generic parameter `L`).
    /// The minimum recommended `output` size is [`BYTES`].
    pub fn crypto_generichash<const L: usize>(
        &self,
        input: &[u8],
        key: Option<&[u8]>,
    ) -> Result<[u8; L], i32> {
        validate_output_size(L);

        let mut buf = MaybeUninit::<[u8; L]>::uninit();

        let (key, keylen) = if let Some(key) = key {
            validate_key_size(key.len());
            (key.as_ptr(), key.len())
        } else {
            (std::ptr::null(), 0)
        };

        let res = unsafe {
            ffi::crypto_generichash(
                buf.as_mut_ptr() as *mut u8,
                L,
                input.as_ptr(),
                input.len() as u64,
                key,
                keylen,
            )
        };

        if res < 0 {
            return Err(res);
        }

        let out = unsafe { buf.assume_init() };
        Ok(out)
    }

    /// Returns initialized [`State`] object providing streaming API
    pub fn crypto_generichash_init<const L: usize>(
        self,
        key: Option<&[u8]>,
    ) -> Result<State<L>, i32> {
        let (key, keylen) = if let Some(key) = key {
            validate_key_size(key.len());
            (key.as_ptr(), key.len())
        } else {
            (std::ptr::null(), 0)
        };

        let mut s = State::new();

        let res =
            unsafe { ffi::crypto_generichash_init(s.state.0.as_mut_ptr() as _, key, keylen, L) };
        if res < 0 {
            Err(res)
        } else {
            Ok(s)
        }
    }
}

/// Struct providing streaming API. Created by calling [`Sodium::crypto_generichash_init`]
#[derive(Default)]
#[non_exhaustive]
pub struct State<const L: usize> {
    state: ffi::crypto_generichash_state,
}

impl<const L: usize> State<L> {
    fn new() -> Self {
        validate_output_size(L);
        Self::default()
    }

    /// Each chunk of the complete message can then be sequentially processed by calling
    pub fn crypto_generichash_update(&mut self, input: &[u8]) -> Result<(), i32> {
        let res = unsafe {
            ffi::crypto_generichash_update(
                self.state.0.as_mut_ptr() as _,
                input.as_ptr(),
                input.len() as u64,
            )
        };
        if res < 0 {
            Err(res)
        } else {
            Ok(())
        }
    }

    /// Completes the operation and returns the final fingerprint
    pub fn crypto_generichash_finalize(&mut self) -> Result<[u8; L], i32> {
        let mut buf = MaybeUninit::<[u8; L]>::uninit();
        let res = unsafe {
            ffi::crypto_generichash_final(
                self.state.0.as_mut_ptr() as _,
                buf.as_mut_ptr() as *mut u8,
                L,
            )
        };
        if res < 0 {
            return Err(res);
        }

        let out = unsafe { buf.assume_init() };
        Ok(out)
    }
}

fn validate_key_size(keylen: usize) {
    assert!(
        keylen >= ffi::crypto_generichash_KEYBYTES_MIN as usize,
        "Minimum key size is {} bytes, provided key has {} bytes",
        ffi::crypto_generichash_KEYBYTES_MIN,
        keylen
    );
    assert!(
        keylen <= ffi::crypto_generichash_KEYBYTES_MAX as usize,
        "Maximum key size is {} bytes, provided key has {} bytes",
        ffi::crypto_generichash_KEYBYTES_MAX,
        keylen
    );
}

fn validate_output_size(outlen: usize) {
    assert!(
        outlen >= ffi::crypto_generichash_BYTES_MIN as usize,
        "Minimum output size is {} bytes, requested size is {} bytes",
        ffi::crypto_generichash_BYTES_MIN,
        outlen
    );
    assert!(
        outlen <= ffi::crypto_generichash_BYTES_MAX as usize,
        "Maximum output size is {} bytes, requested size is {} bytes",
        ffi::crypto_generichash_BYTES_MAX,
        outlen
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sodium_init() {
        assert!(Sodium::new().is_ok())
    }

    #[test]
    fn test_crypto_generichash_keygen() {
        let s = Sodium::new().unwrap();
        let key = s.crypto_generichash_keygen();
        assert_eq!(key.len(), KEYBYTES);
    }

    #[test]
    fn test_crypto_generichash() {
        let s = Sodium::new().unwrap();
        let res = s.crypto_generichash::<BYTES>(b"Some data to hash", None);
        assert!(res.is_ok());

        let hash = hex::encode(res.unwrap());
        assert_eq!(hash.len(), BYTES * 2);
        assert_eq!(
            hash,
            "026da8b2167b96c69190553d962929b375406b913d98239a6c5587ec30f6a42b"
        );

        let res =
            s.crypto_generichash::<64>(b"Arbitrary data to hash", Some(b"random key long enough"));
        assert!(res.is_ok());

        let hash = hex::encode(res.unwrap());
        assert_eq!(hash.len(), 64 * 2);
        assert_eq!(
            hash,
            "b97be52aa6930003fa8adc3417ac014525d0116b5c105e3831d3ad9240c1af35ae99b8fefc6d4f00178c14d34036f9d194dd9690fa809bcbdf9d2cf175da2155"
        );
    }

    #[test]
    fn test_crypto_generichash_streaming_api() {
        let s = Sodium::new().unwrap();
        let state = s.crypto_generichash_init::<BYTES>(None);
        assert!(state.is_ok());

        let mut s = state.unwrap();
        s.crypto_generichash_update(b"Arbitrary data to hash")
            .unwrap();

        s.crypto_generichash_update(b" with some ome other chunk data to hash")
            .unwrap();

        let out = s.crypto_generichash_finalize().unwrap();

        let hash = hex::encode(out);

        assert_eq!(hash.len(), BYTES * 2);
        assert_eq!(
            hash,
            "cbda1fd8764b060084d8a2edf8805e14623c1076297daae77abe5dc913b54d67"
        );
    }
}
