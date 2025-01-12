

#[cfg(test)]
#[cfg(feature = "3des")]
mod tests {
    use data_encryption::{SymmetricEncryption, DesEncryption};
    use data_encryption::StreamEncryption;
    use std::io::{Cursor, Read, Write};
    #[test]
    fn test_des_encrypt_decrypt() {
        let key = vec![0u8; 24]; // Valid 24-byte key for 3DES
        let plaintext = b"Sensitive data!".to_vec(); // Example plaintext

        let des = DesEncryption::new(key.clone()).expect("Failed to create DES instance");

        // Encrypt
        let encrypted = des.encrypt(&plaintext).expect("Encryption failed");
        assert_ne!(plaintext, encrypted); // Encrypted data should not equal plaintext

        // Decrypt
        let decrypted = des.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_invalid_key_length() {
        let invalid_key = vec![0u8; 16]; // Key less than 24 bytes
        let result = DesEncryption::new(invalid_key);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Invalid key length: Triple DES requires a 24-byte key."
        );

        let invalid_key = vec![0u8; 25]; // Key greater than 24 bytes
        let result = DesEncryption::new(invalid_key);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Invalid key length: Triple DES requires a 24-byte key."
        );
    }
    #[test]
    fn test_encrypt_empty_data() {
        let key = vec![0u8; 24]; // Valid 24-byte key
        let plaintext = b"".to_vec(); // Empty plaintext
    
        let des = DesEncryption::new(key.clone()).expect("Failed to create DES instance");
    
        let encrypted = des.encrypt(&plaintext).expect("Encryption failed");
        assert!(!encrypted.is_empty()); // Encrypted data should not be empty
    
        let decrypted = des.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_decrypt_with_invalid_padding() {
        let key = vec![0u8; 24]; // Valid 24-byte key
        let mut ciphertext = vec![0u8; 40]; // Sufficient length for HMAC validation
    
        // Add invalid padding to the ciphertext
        if let Some(last_byte) = ciphertext.last_mut() {
            *last_byte = 9; // Invalid padding value (greater than block size)
        }
    
        let des = DesEncryption::new(key).expect("Failed to create DES instance");
    
        let result = des.decrypt(&ciphertext);
        assert!(result.is_err(), "Decryption should fail with invalid padding");
        assert_eq!(result.err().unwrap(), "Invalid padding detected");
    }
    #[test]
    fn test_encrypt_and_decrypt_large_data() {
        let key = vec![0u8; 24]; // Valid 24-byte key
        let plaintext = vec![0u8; 2048]; // Large data (2KB of zero bytes)
    
        let des = DesEncryption::new(key.clone()).expect("Failed to create DES instance");
    
        let encrypted = des.encrypt(&plaintext).expect("Encryption failed");
        assert!(!encrypted.is_empty());
        assert!(encrypted.len() > plaintext.len()); // Encrypted data includes padding
    
        let decrypted = des.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_encrypt_decrypt_multiple_blocks() {
        let key = vec![0u8; 24]; // Valid 24-byte key
        let plaintext = b"1234567890abcdef1234567890abcdef1234567890abcdef".to_vec(); // 48 bytes (6 blocks)

        let des = DesEncryption::new(key.clone()).expect("Failed to create DES instance");

        let encrypted = des.encrypt(&plaintext).expect("Encryption failed");
        assert!(encrypted.len() % 8 == 0); // Encrypted data should align with block size

        let decrypted = des.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(plaintext, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key = vec![0u8; 24]; // Original key
        let wrong_key = vec![1u8; 24]; // Different key
        let plaintext = b"Sensitive data!".to_vec();
    
        let des_encryptor = DesEncryption::new(key.clone()).expect("Failed to create DES instance");
        let des_decryptor = DesEncryption::new(wrong_key).expect("Failed to create DES instance");
    
        let encrypted = des_encryptor.encrypt(&plaintext).expect("Encryption failed");
        let result = des_decryptor.decrypt(&encrypted);
    
        assert!(result.is_err(), "Decryption with a wrong key should fail");
        assert_eq!(
            result.err().unwrap(),
            "Decryption integrity check failed. Likely wrong key."
        );
    }

    #[test]
    fn test_des_stream_encrypt_decrypt() {
        let key = vec![0u8; 24]; // Valid 24-byte key for 3DES
        let nonce = vec![1u8; 8]; // Valid 8-byte nonce
        let plaintext = b"Streamed sensitive data!".to_vec();

        let des = DesEncryption::new(key.clone()).expect("Failed to create DES instance");

        let mut input = Cursor::new(plaintext.clone());
        let mut encrypted_output = Vec::new();

        // Encrypt stream
        des.encrypt_stream(&mut input, &mut encrypted_output, &key, &nonce)
            .expect("Encryption failed");

        let mut encrypted_input = Cursor::new(encrypted_output);
        let mut decrypted_output = Vec::new();

        // Decrypt stream
        des.decrypt_stream(&mut encrypted_input, &mut decrypted_output, &key, &nonce)
            .expect("Decryption failed");

        assert_eq!(plaintext, decrypted_output, "Decrypted data does not match original data");
    }
}