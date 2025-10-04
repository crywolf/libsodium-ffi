use libsodium_sys::ffi;

pub use ffi::crypto_generichash_BYTES;

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

    /// The crypto_generichash() function puts a fingerprint of the message `input` into `output`. The output size can be chosen by the application.
    /// The minimum recommended output size is `crypto_generichash_BYTES`.
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
    fn test_crypto_generichash() {
        let s = Sodium::new().unwrap();
        let mut output = [0; crypto_generichash_BYTES as usize];

        let res = s.crypto_generichash(b"Arbitrary data to hash", None, &mut output);
        assert!(res.is_ok());
        let out = hex::encode(output);
        assert_eq!(
            out,
            "3dc7925e13e4c5f0f8756af2cc71d5624b58833bb92fa989c3e87d734ee5a600"
        );

        let res = s.crypto_generichash(
            b"Arbitrary data to hash",
            Some(b"some random key long enough"),
            &mut output,
        );
        assert!(res.is_ok());
        let out = hex::encode(output);
        assert_eq!(
            out,
            "74fae2b056fd6d86a63f9e6b6add313d9058736de2485452738d0caf44256072"
        );
    }
}
