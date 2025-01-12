#[cfg(feature="pbkdf")]
#[cfg(test)]
mod tests {
    use data_encryption::{KeyDerivation,PBKDF2};
    #[test]
    fn test_derive_key_basic() {
        let pbkdf2 = PBKDF2 { iterations: 1000 };
        let password = b"secure_password";
        let derived_key = pbkdf2.derive_key(password, 32).expect("Failed to derive key");

        assert_eq!(derived_key.len(), 32);
        assert_ne!(derived_key, vec![0u8; 32]); // Ensure the derived key is not all zeros
    }

    #[test]
    fn test_derive_key_with_empty_password() {
        let pbkdf2 = PBKDF2 { iterations: 1000 };
        let password = b"";
        let derived_key = pbkdf2.derive_key(password, 32).expect("Failed to derive key");

        assert_eq!(derived_key.len(), 32);
        assert_ne!(derived_key, vec![0u8; 32]);
    }

    #[test]
    fn test_derive_key_with_zero_iterations() {
        let pbkdf2 = PBKDF2 { iterations: 0 };
        let password = b"secure_password";
        let result = pbkdf2.derive_key(password, 32);

        assert!(result.is_err(), "Derivation should fail with zero iterations");
    }

    #[test]
    fn test_derive_key_with_large_output_length() {
        let pbkdf2 = PBKDF2 { iterations: 1000 };
        let password = b"secure_password";
        let derived_key = pbkdf2
            .derive_key(password, 1024)
            .expect("Failed to derive key");

        assert_eq!(derived_key.len(), 1024);
        assert_ne!(derived_key, vec![0u8; 1024]);
    }

}
