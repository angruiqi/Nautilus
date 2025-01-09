
use rand_core::{OsRng, RngCore};

/// Generate a secure random salt of the specified length.

pub fn generate_secure_salt(length: usize) -> Vec<u8> {
    let mut salt = vec![0u8; length];
    OsRng.fill_bytes(&mut salt);
    salt
}