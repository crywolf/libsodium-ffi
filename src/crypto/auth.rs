//! Message authentication using authentication tag (MAC) for a message and a secret key

use std::mem::MaybeUninit;

use libsodium_sys::ffi;

use crate::Sodium;

/// Length of the generated tag
pub const BYTES: usize = ffi::crypto_auth_BYTES as usize;
/// Length of the generated key
pub const KEYBYTES: usize = ffi::crypto_auth_KEYBYTES as usize;

/// Trait for message authentication using authentication tag (MAC) for a message and a secret key
///
/// This operation computes an authentication tag for a message and a secret key, and provides a way to verify that a given tag is valid for a given message and a key.
///
/// The function computing the tag deterministic: the same (message, key) tuple will always produce the same output.
/// However, even if the message is public, knowing the key is required in order to be able to compute a valid tag. Therefore, the key should remain confidential. The tag, however, can be public.
///
/// A typical use case is:
///
/// 1. A prepares a message, add an authentication tag, sends it to B
/// 2. A doesn’t store the message
/// 3. Later on, B sends the message and the authentication tag to A
/// 4. A uses the authentication tag to verify that it created this message.
///
/// This operation does not encrypt the message. It only computes and verifies an authentication tag.
///
pub trait Auth {
    /// Computes a tag [message authentication code (MAC)] for the message using specified key
    fn auth_mac(&self, message: &[u8], key: &[u8]) -> Result<[u8; BYTES], String>;
    /// Helper function that creates a random key
    fn auth_keygen(&self) -> [u8; KEYBYTES];
    /// Verifies that the tag is a valid tag for the message and the key
    fn auth_verify(&self, tag: &[u8], message: &[u8], key: &[u8]) -> Result<bool, String>;
}

impl Auth for Sodium {
    fn auth_mac(&self, message: &[u8], key: &[u8]) -> Result<[u8; BYTES], String> {
        let mut buf = MaybeUninit::<[u8; BYTES]>::uninit();

        let res = unsafe {
            ffi::crypto_auth(
                buf.as_mut_ptr() as *mut u8,
                message.as_ptr(),
                message.len() as u64,
                key.as_ptr(),
            )
        };

        if res < 0 {
            return Err(format!("libsodium call failed with code {}", res));
        }

        let out = unsafe { buf.assume_init() };
        Ok(out)
    }

    fn auth_keygen(&self) -> [u8; KEYBYTES] {
        let mut buf = MaybeUninit::<[u8; KEYBYTES]>::uninit();

        unsafe { ffi::crypto_auth_keygen(buf.as_mut_ptr() as *mut u8) }

        unsafe { buf.assume_init() }
    }

    fn auth_verify(&self, tag: &[u8], message: &[u8], key: &[u8]) -> Result<bool, String> {
        let res = unsafe {
            ffi::crypto_auth_verify(
                tag.as_ptr(),
                message.as_ptr(),
                message.len() as u64,
                key.as_ptr(),
            )
        };

        if res == 0 {
            return Ok(true);
        }

        if res == -1 {
            return Ok(false);
        }

        Err(format!("libsodium call failed with code {}", res))
    }
}
