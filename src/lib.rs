pub mod crypto;
pub mod randombytes;

use libsodium_sys::ffi;

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
}
