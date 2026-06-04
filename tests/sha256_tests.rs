//! SHA-256 (FIPS 180-4) known-answer tests, against the NIST example vectors.

use gpt_forensic::sha256::{digest, hex};

#[test]
fn empty_string_vector() {
    assert_eq!(
        hex(&digest(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn abc_vector() {
    // FIPS 180-4 / NIST: SHA-256("abc").
    assert_eq!(
        hex(&digest(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn two_block_vector() {
    let msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    assert_eq!(
        hex(&digest(msg)),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    );
}

#[test]
fn digest_is_32_bytes() {
    assert_eq!(digest(b"anything").len(), 32);
}
