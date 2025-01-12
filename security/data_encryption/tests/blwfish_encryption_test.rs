#[cfg(test)]
#[cfg(feature = "blwfish")]
mod tests {
    use data_encryption::{SymmetricEncryption, BlowfishEncryption,StreamEncryption};
    use std::io::Cursor;
    #[test]
    fn test_blowfish_encrypt_decrypt() {
        let key = b"super_secret_key".to_vec(); // Valid key
        let plaintext = b"Sensitive Data".to_vec(); // Example plaintext

        let blowfish = BlowfishEncryption::new(key.clone()).expect("Failed to create Blowfish instance");

        // Encrypt
        let encrypted = blowfish.encrypt(&plaintext).expect("Encryption failed");
        assert_ne!(plaintext, encrypted); // Encrypted data should not equal plaintext

        // Decrypt
        let decrypted = blowfish.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_invalid_key_length() {
        let invalid_key = b"sho".to_vec(); // Key less than 4 bytes
        let result = BlowfishEncryption::new(invalid_key);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Invalid key length: Blowfish requires a key between 4 and 56 bytes."
        );

        let invalid_key = vec![0u8; 57]; // Key greater than 56 bytes
        let result = BlowfishEncryption::new(invalid_key);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Invalid key length: Blowfish requires a key between 4 and 56 bytes."
        );
    }

    #[test]
    fn test_encrypt_empty_data() {
        let key = b"valid_key".to_vec(); // Valid key
        let plaintext = b"".to_vec(); // Empty data

        let blowfish = BlowfishEncryption::new(key.clone()).expect("Failed to create Blowfish instance");

        let encrypted = blowfish.encrypt(&plaintext).expect("Encryption failed");
        assert!(!encrypted.is_empty()); // Encrypted data should not be empty

        let decrypted = blowfish.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_decrypt_with_invalid_padding() {
        let key = b"valid_key".to_vec(); // Valid key
        let ciphertext = vec![0u8; 16]; // Ciphertext with invalid padding

        let blowfish = BlowfishEncryption::new(key.clone()).expect("Failed to create Blowfish instance");

        let result = blowfish.decrypt(&ciphertext);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Invalid padding detected");
    }

    #[test]
    fn test_encrypt_and_decrypt_large_data() {
        let key = b"another_secret_key".to_vec(); // Valid key
        let plaintext = vec![0u8; 1024]; // Large data (1KB of zero bytes)

        let blowfish = BlowfishEncryption::new(key.clone()).expect("Failed to create Blowfish instance");

        let encrypted = blowfish.encrypt(&plaintext).expect("Encryption failed");
        assert!(!encrypted.is_empty());
        assert!(encrypted.len() > plaintext.len()); // Encrypted data includes padding

        let decrypted = blowfish.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_encrypt_decrypt_multiple_blocks() {
        let key = b"block_test_key".to_vec(); // Valid key
        let plaintext = b"1234567890abcdef1234567890abcdef1234567890abcdef".to_vec(); // 48 bytes (6 blocks)

        let blowfish = BlowfishEncryption::new(key.clone()).expect("Failed to create Blowfish instance");

        let encrypted = blowfish.encrypt(&plaintext).expect("Encryption failed");
        assert!(encrypted.len() % 8 == 0); // Encrypted data should align with block size

        let decrypted = blowfish.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_blowfish_stream_encrypt_decrypt() {
        let key = b"stream_key".to_vec();
        let plaintext = b"Stream encryption test data.".to_vec();

        let blowfish = BlowfishEncryption::new(key.clone()).expect("Failed to create Blowfish instance");

        let mut input = Cursor::new(plaintext.clone());
        let mut encrypted_output = Vec::new();

        // Encrypt
        blowfish
            .encrypt_stream(&mut input, &mut encrypted_output, &key, &[])
            .expect("Encryption failed");

        let mut encrypted_input = Cursor::new(encrypted_output);
        let mut decrypted_output = Vec::new();

        // Decrypt
        blowfish
            .decrypt_stream(&mut encrypted_input, &mut decrypted_output, &key, &[])
            .expect("Decryption failed");

        assert_eq!(plaintext, decrypted_output);
    }
}
