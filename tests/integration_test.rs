use libsodium_ffi::{crypto_generichash_BYTES, Sodium};

#[test]
fn test_crypto_generichash_without_key() {
    let s = Sodium::new().unwrap();
    let mut output = [0; crypto_generichash_BYTES as usize];

    let res = s.crypto_generichash(b"Arbitrary data to hash", None, &mut output);
    assert!(res.is_ok());
    let out = hex::encode(output);
    assert_eq!(
        out,
        "3dc7925e13e4c5f0f8756af2cc71d5624b58833bb92fa989c3e87d734ee5a600"
    );
}

#[test]
fn test_crypto_generichash_with_key() {
    let s = Sodium::new().unwrap();
    let mut output = [0; crypto_generichash_BYTES as usize];

    let key = b"some random key long enough";
    let res = s.crypto_generichash(b"Arbitrary data to hash", Some(key), &mut output);
    assert!(res.is_ok());
    let out = hex::encode(output);
    assert_eq!(
        out,
        "74fae2b056fd6d86a63f9e6b6add313d9058736de2485452738d0caf44256072",
    );
}
