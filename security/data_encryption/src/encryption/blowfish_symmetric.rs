#[cfg(feature = "blwfish")]
use blowfish::cipher::{BlockEncrypt, BlockDecrypt, KeyInit};
#[cfg(feature = "blwfish")]
use blowfish::Blowfish;
#[cfg(feature = "blwfish")]
use crate::SymmetricEncryption;
#[cfg(feature = "blwfish")]
use std::io::{Read, Write};
#[cfg(feature = "blwfish")]
use crate::StreamEncryption;
#[cfg(feature = "blwfish")]
pub struct BlowfishEncryption {
    cipher: Blowfish,
}

#[cfg(feature = "blwfish")]
impl BlowfishEncryption {
    /// Creates a new `BlowfishEncryption` instance.
    pub fn new(key: Vec<u8>) -> Result<Self, String> {
        if key.len() < 4 || key.len() > 56 {
            return Err("Invalid key length: Blowfish requires a key between 4 and 56 bytes.".to_string());
        }
        Ok(Self {
            cipher: Blowfish::new_from_slice(&key).map_err(|e| e.to_string())?,
        })
    }
}

#[cfg(feature = "blwfish")]
impl SymmetricEncryption for BlowfishEncryption {
    type Error = String;

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut result = Vec::new();

        // Add padding to plaintext
        let mut padded_plaintext = plaintext.to_vec();
        let padding_len = 8 - (padded_plaintext.len() % 8);
        padded_plaintext.extend(vec![padding_len as u8; padding_len]);

        // Process padded plaintext in 8-byte chunks
        for chunk in padded_plaintext.chunks(8) {
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            self.cipher.encrypt_block(&mut block.into());
            result.extend_from_slice(&block);
        }

        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let mut result = Vec::new();
    
        // Process ciphertext in 8-byte chunks
        for chunk in ciphertext.chunks(8) {
            if chunk.len() != 8 {
                return Err("Ciphertext length is not a multiple of block size".to_string());
            }
    
            let mut block = [0u8; 8];
            block.copy_from_slice(chunk);
            self.cipher.decrypt_block(&mut block.into());
            result.extend_from_slice(&block);
        }
    
        // Remove padding
        if let Some(&padding_len) = result.last() {
            let padding_len = padding_len as usize;
    
            // Check if padding length is valid
            if padding_len == 0 || padding_len > 8 || result.len() < padding_len {
                return Err("Invalid padding detected".to_string());
            }
    
            // Verify all padding bytes
            let padding_start = result.len() - padding_len;
            if !result[padding_start..].iter().all(|&byte| byte as usize == padding_len) {
                return Err("Invalid padding detected".to_string());
            }
    
            // Truncate padding
            result.truncate(result.len() - padding_len);
        } else {
            return Err("Invalid padding: ciphertext is empty".to_string());
        }
    
        Ok(result)
    }
}



#[cfg(feature = "blwfish")]
impl StreamEncryption for BlowfishEncryption {
    type Error = String;

    fn encrypt_stream<R: Read, W: Write>(
        &self,
        mut input: R,
        mut output: W,
        _key: &[u8], // Blowfish uses the internal key, this can be ignored
        _nonce: &[u8], // Blowfish doesn't use a nonce, this can be ignored
    ) -> Result<(), Self::Error> {
        let mut buffer = [0u8; 8]; // Blowfish uses an 8-byte block size

        loop {
            let bytes_read = input.read(&mut buffer).map_err(|e| e.to_string())?;

            if bytes_read == 0 {
                break; // End of input stream
            }

            let mut block = [0u8; 8];
            block[..bytes_read].copy_from_slice(&buffer[..bytes_read]);

            // Add padding if it's the last block
            if bytes_read < 8 {
                let padding_len = 8 - bytes_read;
                block[bytes_read..].fill(padding_len as u8);
            }

            self.cipher.encrypt_block(&mut block.into());
            output.write_all(&block).map_err(|e| e.to_string())?;
        }

        Ok(())
    }

    fn decrypt_stream<R: Read, W: Write>(
        &self,
        mut input: R,
        mut output: W,
        _key: &[u8], // Blowfish uses the internal key, this can be ignored
        _nonce: &[u8], // Blowfish doesn't use a nonce, this can be ignored
    ) -> Result<(), Self::Error> {
        let mut buffer = [0u8; 8]; // Blowfish uses an 8-byte block size
        let mut result = Vec::new();

        loop {
            let bytes_read = input.read(&mut buffer).map_err(|e| e.to_string())?;

            if bytes_read == 0 {
                break; // End of input stream
            }

            if bytes_read != 8 {
                return Err("Ciphertext length is not a multiple of block size".to_string());
            }

            let mut block = [0u8; 8];
            block.copy_from_slice(&buffer);

            self.cipher.decrypt_block(&mut block.into());
            result.extend_from_slice(&block);
        }

        // Remove padding
        if let Some(&padding_len) = result.last() {
            let padding_len = padding_len as usize;

            // Check if padding length is valid
            if padding_len == 0 || padding_len > 8 || result.len() < padding_len {
                return Err("Invalid padding detected".to_string());
            }

            // Verify all padding bytes
            let padding_start = result.len() - padding_len;
            if !result[padding_start..].iter().all(|&byte| byte as usize == padding_len) {
                return Err("Invalid padding detected".to_string());
            }

            // Truncate padding
            result.truncate(result.len() - padding_len);
        } else {
            return Err("Invalid padding: ciphertext is empty".to_string());
        }

        output.write_all(&result).map_err(|e| e.to_string())?;
        Ok(())
    }
}

#[cfg(test)]
#[cfg(feature = "blwfish")]
mod tests {
    use crate::{SymmetricEncryption, BlowfishEncryption,StreamEncryption};
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
