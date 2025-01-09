#[cfg(feature = "chacha20")]
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
#[cfg(feature = "chacha20")]
use crate::{SymmetricEncryption, StreamEncryption};

#[cfg(feature = "chacha20")]
use std::io::{Read, Write};

#[cfg(feature = "chacha20")]
pub struct ChaCha20Encryption {
    key: Vec<u8>,
    nonce: Vec<u8>,
}

#[cfg(feature = "chacha20")]
impl ChaCha20Encryption {
    /// Creates a new instance of `ChaCha20Encryption`.
    pub fn new(key: Vec<u8>, nonce: Vec<u8>) -> Result<Self, String> {
        if key.len() != 32 {
            return Err("Invalid key length: ChaCha20 requires a 256-bit key (32 bytes).".to_string());
        }
        if nonce.len() != 12 {
            return Err("Invalid nonce length: ChaCha20 requires a 12-byte nonce.".to_string());
        }
        Ok(Self { key, nonce })
    }

    fn increment_nonce(nonce: &mut [u8; 12]) {
        for byte in nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
}
#[cfg(feature = "chacha20")]
impl SymmetricEncryption for ChaCha20Encryption {
    type Error = String;

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let nonce = chacha20poly1305::Nonce::from_slice(&self.nonce); // Validated in `new`
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let nonce = chacha20poly1305::Nonce::from_slice(&self.nonce); // Validated in `new`
        let cipher = ChaCha20Poly1305::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())
    }
}

#[cfg(feature = "chacha20")]
impl StreamEncryption for ChaCha20Encryption {
    type Error = String;

    fn encrypt_stream<R: Read, W: Write>(
        &self,
        mut input: R,
        mut output: W,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<(), Self::Error> {
        let mut nonce = *<&[u8; 12]>::try_from(nonce).map_err(|_| "Invalid nonce length".to_string())?;
        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; 1024];

        while let Ok(bytes_read) = input.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }

            let encrypted_chunk = cipher
                .encrypt(chacha20poly1305::Nonce::from_slice(&nonce), &buffer[..bytes_read])
                .map_err(|e| e.to_string())?;
            output.write_all(&encrypted_chunk).map_err(|e| e.to_string())?;
            Self::increment_nonce(&mut nonce);
        }

        Ok(())
    }

    fn decrypt_stream<R: Read, W: Write>(
        &self,
        mut input: R,
        mut output: W,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<(), Self::Error> {
        let mut nonce = *<&[u8; 12]>::try_from(nonce).map_err(|_| "Invalid nonce length".to_string())?;
        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; 1040];

        while let Ok(bytes_read) = input.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }

            let decrypted_chunk = cipher
                .decrypt(chacha20poly1305::Nonce::from_slice(&nonce), &buffer[..bytes_read])
                .map_err(|e| e.to_string())?;
            output.write_all(&decrypted_chunk).map_err(|e| e.to_string())?;
            Self::increment_nonce(&mut nonce);
        }

        Ok(())
    }
}


#[cfg(test)]
#[cfg(feature = "chacha20")]
mod tests {
    use crate::{SymmetricEncryption, ChaCha20Encryption};

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
