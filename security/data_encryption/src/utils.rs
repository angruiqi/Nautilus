// security\data_encryption\src\utils.rs
use rand_core::{OsRng, RngCore};

/// Generate a secure random salt of the specified length.
pub fn generate_secure_salt(length: usize) -> Vec<u8> {
    let mut salt = vec![0u8; length];
    OsRng.fill_bytes(&mut salt); // Explicitly use `fill_bytes` for better readability.
    salt
}

/// Generates a secure random key of the given size (in bytes).
pub fn generate_random_key(size: usize) -> Vec<u8> {
    let mut key = vec![0u8; size];
    OsRng.fill_bytes(&mut key); // Consistency with `generate_secure_salt`.
    key
}

/// Generates a secure random nonce of the given size (in bytes).
pub fn generate_random_nonce(size: usize) -> Vec<u8> {
    let mut nonce = vec![0u8; size];
    OsRng.fill_bytes(&mut nonce); // Consistency with other functions.
    nonce
}