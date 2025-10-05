use libsodium_ffi::{Sodium, BYTES, KEYBYTES};

#[test]
fn test_crypto_generichash_keygen() {
    let s = Sodium::new().unwrap();
    let key = s.crypto_generichash_keygen();
    assert_eq!(key.len(), KEYBYTES);
}

#[test]
fn test_crypto_generichash_without_key() {
    let s = Sodium::new().unwrap();
    let res = s.crypto_generichash::<BYTES>(b"Arbitrary data to hash", None);
    assert!(res.is_ok());

    let hash = hex::encode(res.unwrap());
    assert_eq!(
        hash,
        "3dc7925e13e4c5f0f8756af2cc71d5624b58833bb92fa989c3e87d734ee5a600"
    );
}

#[test]
fn test_crypto_generichash_with_key() {
    let s = Sodium::new().unwrap();
    let key = b"some random key long enough";
    let res = s.crypto_generichash::<BYTES>(b"Arbitrary data to hash", Some(key));
    assert!(res.is_ok());

    let hash = hex::encode(res.unwrap());
    assert_eq!(
        hash,
        "74fae2b056fd6d86a63f9e6b6add313d9058736de2485452738d0caf44256072",
    );
}

#[test]
fn test_crypto_generichash_streaming_api() {
    let s = Sodium::new().unwrap();
    let key = b"some random key long enough";
    let state = s.crypto_generichash_init(Some(key), BYTES);
    assert!(state.is_ok());

    let mut s = state.unwrap();
    s.crypto_generichash_update(b"Arbitrary data to hash")
        .unwrap();

    s.crypto_generichash_update(b" with some ome other chunk data to hash")
        .unwrap();

    s.crypto_generichash_update(b" and some other stuff.")
        .unwrap();

    let out = s.crypto_generichash_finalize().unwrap();

    let hash = hex::encode(out);

    assert_eq!(hash.len(), BYTES * 2);
    assert_eq!(
        hash,
        "24924849ecf0acff5ff70dd4cf67eb843588f623365e4fbaeffca8a0c15ee6a8"
    );
}
