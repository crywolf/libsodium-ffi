use std::mem::MaybeUninit;

use libsodium_sys::ffi;

/// The minimum recommended output size
pub const BYTES: usize = ffi::crypto_generichash_BYTES as usize;
/// The recommended key size
pub const KEYBYTES: usize = ffi::crypto_generichash_KEYBYTES as usize;

#[non_exhaustive] // forces user to use constructor (ie. `new` method)
/// Sodium library object
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

    /// Creates a key of the recommended length [KEYBYTES]
    pub fn crypto_generichash_keygen(&self) -> Vec<u8> {
        let mut buf = MaybeUninit::<[u8; KEYBYTES]>::uninit();

        unsafe { ffi::crypto_generichash_keygen(buf.as_mut_ptr() as *mut u8) };
        unsafe { buf.assume_init() }.to_vec()
    }

    /// Puts a fingerprint of the message `input` into `output`. The output size can be chosen by the application.
    /// The minimum recommended `output` size is [BYTES].
    pub fn crypto_generichash(
        &self,
        input: &[u8],
        key: Option<&[u8]>,
        output: &mut [u8],
    ) -> Result<(), i32> {
        assert!(output.len() >= ffi::crypto_generichash_BYTES_MIN as usize);
        assert!(output.len() <= ffi::crypto_generichash_BYTES_MAX as usize);

        let (key, keylen) = if let Some(key) = key {
            assert!(key.len() >= ffi::crypto_generichash_KEYBYTES_MIN as usize);
            assert!(key.len() <= ffi::crypto_generichash_KEYBYTES_MAX as usize);
            (key.as_ptr(), key.len())
        } else {
            (std::ptr::null(), 0)
        };

        let res = unsafe {
            ffi::crypto_generichash(
                output.as_mut_ptr(),
                output.len(),
                input.as_ptr(),
                input.len() as u64,
                key,
                keylen,
            )
        };

        if res < 0 {
            Err(res)
        } else {
            Ok(())
        }
    }

    /// Returns initialized [State] object providing streaming API
    pub fn crypto_generichash_init(self, key: Option<&[u8]>, outlen: usize) -> Result<State, i32> {
        let (key, keylen) = if let Some(key) = key {
            assert!(key.len() >= ffi::crypto_generichash_KEYBYTES_MIN as usize);
            assert!(key.len() <= ffi::crypto_generichash_KEYBYTES_MAX as usize);
            (key.as_ptr(), key.len())
        } else {
            (std::ptr::null(), 0)
        };

        let mut s = State::new(outlen);

        let res = unsafe {
            ffi::crypto_generichash_init(s.state.0.as_mut_ptr() as _, key, keylen, s.outlen)
        };
        if res < 0 {
            Err(res)
        } else {
            Ok(s)
        }
    }
}

#[derive(Default)]
#[non_exhaustive]
/// Struct providing streaming API
pub struct State {
    state: ffi::crypto_generichash_state,
    outlen: usize,
}

impl State {
    fn new(outlen: usize) -> Self {
        assert!(outlen >= ffi::crypto_generichash_BYTES_MIN as usize);
        assert!(outlen <= ffi::crypto_generichash_BYTES_MAX as usize);

        Self {
            outlen,
            ..Default::default()
        }
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
    pub fn crypto_generichash_finalize(&mut self) -> Result<Vec<u8>, i32> {
        let mut buf = vec![0; self.outlen];
        let res = unsafe {
            ffi::crypto_generichash_final(
                self.state.0.as_mut_ptr() as _,
                buf.as_mut_ptr(),
                self.outlen,
            )
        };
        if res < 0 {
            return Err(res);
        }

        Ok(buf)
    }
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
        let mut output = [0; BYTES];

        let res = s.crypto_generichash(b"Some data to hash", None, &mut output);
        assert!(res.is_ok());
        let hash = hex::encode(output);
        assert_eq!(
            hash,
            "026da8b2167b96c69190553d962929b375406b913d98239a6c5587ec30f6a42b"
        );

        let res = s.crypto_generichash(
            b"Arbitrary data to hash",
            Some(b"random key long enough"),
            &mut output,
        );
        assert!(res.is_ok());
        let hash = hex::encode(output);
        assert_eq!(
            hash,
            "023dd0b5ee086a5ad1ff1a0df2288bfd8297066914dc3c944c352ed79413af5f"
        );
    }

    #[test]
    fn test_crypto_generichash_streaming_api() {
        let s = Sodium::new().unwrap();
        let state = s.crypto_generichash_init(None, BYTES);
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
