use std::mem::MaybeUninit;

use libsodium_sys::ffi;

/// The minimum recommended output size
pub const BYTES: usize = ffi::crypto_generichash_BYTES as usize;

/// The recommended key size
pub const KEYBYTES: usize = ffi::crypto_generichash_KEYBYTES as usize;

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

    /// Creates a key k of the recommended length [KEYBYTES]
    pub fn crypto_generichash_keygen(&self) -> Vec<u8> {
        let mut buf = MaybeUninit::<[u8; KEYBYTES]>::uninit();

        unsafe { ffi::crypto_generichash_keygen(buf.as_mut_ptr() as *mut u8) };
        unsafe { buf.assume_init() }.to_vec()
    }

    /// Puts a fingerprint of the message `input` into `output`. The output size can be chosen by the application.
    /// The minimum recommended output size is [BYTES].
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
}
