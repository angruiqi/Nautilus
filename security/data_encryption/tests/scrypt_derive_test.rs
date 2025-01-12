#[cfg(test)]
#[cfg(feature = "scrypt_derive")]
mod tests {
    use scrypt::Params;
    use data_encryption::{KeyDerivation,Scrypt};
    #[test]
    fn test_derive_key_basic() {
        let params = Params::new(15, 8, 1, 32).expect("Failed to create params");
        let scrypt = Scrypt { params };
        let password = b"password";
        let key = scrypt
            .derive_key(password, 32)
            .expect("Key derivation failed");
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_different_salts() {
        let params = Params::new(15, 8, 1, 32).expect("Failed to create params");
        let scrypt = Scrypt { params };
        let password = b"password";

        let key1 = scrypt
            .derive_key(password, 32)
            .expect("Key derivation failed");
        let key2 = scrypt
            .derive_key(password, 32)
            .expect("Key derivation failed");

        assert_ne!(key1, key2); // Different salts produce different outputs
    }

    #[test]
    fn test_large_output_length() {
        let params = Params::new(15, 8, 1, 32).expect("Failed to create params");
        let scrypt = Scrypt { params };
        let password = b"password";
        // Attempt a valid large output length (1MB)
        let result = scrypt.derive_key(password, 1024 * 1024); // 1MB
        assert!(result.is_ok(), "Derivation with max allowed output length should succeed");
    
        // Attempt an invalid large output length (>1MB)
        let result = scrypt.derive_key(password, 10 * 1024 * 1024); // 10MB
        assert!(
            result.is_err(),
            "Derivation with excessively large output length should fail"
        );
    }

    #[test]
    fn test_empty_password_and_salt() {
        let params = Params::new(15, 8, 1, 32).expect("Failed to create params");
        let scrypt = Scrypt { params };
        let password = b"";

        let key = scrypt
            .derive_key(password, 32)
            .expect("Key derivation failed");

        assert_eq!(key.len(), 32); // Ensure output length matches requested size
    }

    #[test]
    fn test_invalid_params() {
        // Invalid parameters (e.g., block size too large)
        let result = Params::new(15, u32::MAX, 1, 32);
        assert!(result.is_err(), "Invalid parameters should result in an error");
    }
}