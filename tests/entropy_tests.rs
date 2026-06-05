//! Shannon entropy over byte slices (used for hidden encrypted-volume detection).

use gpt_forensic::entropy::shannon;

#[test]
fn all_zero_is_zero() {
    assert!(shannon(&[0u8; 64]).abs() < 1e-12);
}

#[test]
fn empty_is_zero() {
    assert!(shannon(&[]).abs() < 1e-12);
}

#[test]
fn two_equiprobable_values_is_one_bit() {
    let mut data = vec![0u8; 128];
    for b in data.iter_mut().skip(64) {
        *b = 0xFF;
    }
    assert!(
        (shannon(&data) - 1.0).abs() < 1e-9,
        "got {}",
        shannon(&data)
    );
}

#[test]
fn full_byte_range_is_eight_bits() {
    let data: Vec<u8> = (0..=255u8).collect();
    assert!(
        (shannon(&data) - 8.0).abs() < 1e-9,
        "got {}",
        shannon(&data)
    );
}
