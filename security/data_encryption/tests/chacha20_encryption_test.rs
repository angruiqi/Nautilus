#[cfg(test)]
#[cfg(feature = "chacha20")]
mod tests {
    use data_encryption::{SymmetricEncryption, ChaCha20Encryption};

    #[test]
    fn test_chacha20_encrypt_decrypt() {
        let key = vec![0u8; 32]; // Valid 256-bit key
        let nonce = vec![1u8; 12]; // Valid 12-byte nonce
        let plaintext = b"Sensitive data!".to_vec();

        let chacha = ChaCha20Encryption::new(key.clone(), nonce.clone())
            .expect("Failed to create ChaCha20 instance");

        // Encrypt
        let encrypted = chacha.encrypt(&plaintext).expect("Encryption failed");
        assert_ne!(plaintext, encrypted); // Encrypted data should not equal plaintext

        // Decrypt
        let decrypted = chacha.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_invalid_key_length() {
        let invalid_key = vec![0u8; 16]; // Invalid key length
        let nonce = vec![1u8; 12]; // Valid nonce

        let result = ChaCha20Encryption::new(invalid_key, nonce);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Invalid key length: ChaCha20 requires a 256-bit key (32 bytes)."
        );
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = vec![0u8; 32]; // Valid 256-bit key
        let invalid_nonce = vec![1u8; 8]; // Invalid nonce length

        let result = ChaCha20Encryption::new(key, invalid_nonce);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Invalid nonce length: ChaCha20 requires a 12-byte nonce."
        );
    }

    #[test]
    fn test_encrypt_empty_data() {
        let key = vec![0u8; 32]; // Valid 256-bit key
        let nonce = vec![0u8; 12]; // Valid 12-byte nonce
        let plaintext = b"".to_vec(); // Empty data

        let chacha = ChaCha20Encryption::new(key.clone(), nonce.clone())
            .expect("Failed to create ChaCha20 instance");

        let encrypted = chacha.encrypt(&plaintext).expect("Encryption failed");
        assert!(!encrypted.is_empty()); // Encrypted data should not be empty

        let decrypted = chacha.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key = vec![0u8; 32]; // Original key
        let wrong_key = vec![1u8; 32]; // Different key
        let nonce = vec![0u8; 12]; // Valid 12-byte nonce
        let plaintext = b"Sensitive data!".to_vec();

        let chacha_encryptor = ChaCha20Encryption::new(key.clone(), nonce.clone())
            .expect("Failed to create ChaCha20 instance");
        let chacha_decryptor = ChaCha20Encryption::new(wrong_key, nonce.clone())
            .expect("Failed to create ChaCha20 instance");

        let encrypted = chacha_encryptor.encrypt(&plaintext).expect("Encryption failed");
        let result = chacha_decryptor.decrypt(&encrypted);

        assert!(result.is_err()); // Decryption should fail with the wrong key
    }

    #[test]
    fn test_decrypt_with_wrong_nonce() {
        let key = vec![0u8; 32]; // Valid 256-bit key
        let nonce = vec![0u8; 12]; // Original nonce
        let wrong_nonce = vec![1u8; 12]; // Different nonce
        let plaintext = b"Sensitive data!".to_vec();

        let chacha_encryptor = ChaCha20Encryption::new(key.clone(), nonce.clone())
            .expect("Failed to create ChaCha20 instance");
        let chacha_decryptor = ChaCha20Encryption::new(key.clone(), wrong_nonce)
            .expect("Failed to create ChaCha20 instance");

        let encrypted = chacha_encryptor.encrypt(&plaintext).expect("Encryption failed");
        let result = chacha_decryptor.decrypt(&encrypted);

        assert!(result.is_err()); // Decryption should fail with the wrong nonce
    }

    #[test]
    fn test_encrypt_and_decrypt_large_data() {
        let key = vec![0u8; 32]; // Valid 256-bit key
        let nonce = vec![1u8; 12]; // Valid 12-byte nonce
        let plaintext = vec![0u8; 1024]; // 1KB of data

        let chacha = ChaCha20Encryption::new(key.clone(), nonce.clone())
            .expect("Failed to create ChaCha20 instance");

        let encrypted = chacha.encrypt(&plaintext).expect("Encryption failed");
        assert!(!encrypted.is_empty()); // Encrypted data should not be empty

        let decrypted = chacha.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }
}
