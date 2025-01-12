
#[cfg(feature = "argon")]
#[cfg(test)]
mod tests {
    use data_encryption::{KeyDerivation,Argon2KeyDerivation};

    #[test]
    fn test_derive_key_basic() {
        let derivation = Argon2KeyDerivation::new(65536, 3, 1).expect("Failed to create Argon2 instance");
        let password = b"password";
        let key = derivation
            .derive_key(password, 32)
            .expect("Key derivation failed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_argon2_different_salts() {
        let derivation = Argon2KeyDerivation::new(4096, 3, 1).expect("Failed to create Argon2 instance");
        let password = b"password";
        let key1 = derivation.derive_key(password, 32).expect("Key derivation failed");
        let key2 = derivation.derive_key(password, 32).expect("Key derivation failed");

        assert_ne!(key1, key2); // Keys derived with different salts should be different
    }

    #[test]
    fn test_derive_key_with_large_output_length() {
        let derivation = Argon2KeyDerivation::new(65536, 3, 1).expect("Failed to create Argon2 instance");
        let password = b"password";
        let key = derivation
            .derive_key(password, 1024) // Large output length
            .expect("Key derivation failed");
        assert_eq!(key.len(), 1024);
    }

    #[test]
    fn test_argon2_empty_password_and_salt() {
        let derivation = Argon2KeyDerivation::new(4096, 3, 1).expect("Failed to create Argon2 instance");
        let password = b"";
        let key = derivation.derive_key(password, 32).expect("Key derivation failed");

        assert_eq!(key.len(), 32); // Ensure output length matches requested size
    }

    #[test]
    fn test_argon2_large_memory() {
        let derivation = Argon2KeyDerivation::new(64 * 1024, 3, 1).expect("Failed to create Argon2 instance"); // 64 MB
        let password = b"password";
        let key = derivation.derive_key(password, 32).expect("Key derivation failed");

        assert_eq!(key.len(), 32);
    }
}