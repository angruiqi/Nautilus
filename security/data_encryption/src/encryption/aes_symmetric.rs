#[cfg(feature = "aes")]
use crate::SymmetricEncryption;
#[cfg(feature = "aes")]
use crate::StreamEncryption;
#[cfg(feature = "aes")]
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes128Gcm, Aes256Gcm, Nonce,
};
#[cfg(feature = "aes")]
use std::io::{Read, Write};
#[cfg(feature = "aes")]
use zeroize::Zeroize;


#[cfg(feature = "aes")]
#[derive(Debug, Clone)]
pub enum AesKeySize {
    Aes128,
    Aes256,
}
#[cfg(feature = "aes")]
#[derive(Clone)]
pub struct AesGcmEncryption {
    key_size: AesKeySize,
    key: Vec<u8>,
    nonce: Vec<u8>,
}

#[cfg(feature = "aes")]
impl Drop for AesGcmEncryption {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
    }
}
#[cfg(feature = "aes")]
impl AesGcmEncryption {
    /// Creates a new `AesGcmEncryption` instance.
    pub fn new(key_size: AesKeySize, key: Vec<u8>, nonce: Vec<u8>) -> Result<Self, String> {
        let expected_key_len = match key_size {
            AesKeySize::Aes128 => 16,
            AesKeySize::Aes256 => 32,
        };

        if key.len() != expected_key_len {
            return Err(format!(
                "Invalid key length for {:?}: expected {}, got {}",
                key_size, expected_key_len, key.len()
            ));
        }

        if nonce.len() != 12 {
            return Err("Invalid nonce length: expected 12 bytes.".to_string());
        }

        Ok(Self {
            key_size,
            key,
            nonce,
        })
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


#[cfg(feature = "aes")]
impl SymmetricEncryption for AesGcmEncryption {
    type Error = String;

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let nonce = Nonce::from_slice(&self.nonce); // 12-byte nonce
        match self.key_size {
            AesKeySize::Aes128 => {
                let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())
            }
            AesKeySize::Aes256 => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())
            }
        }
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let nonce = Nonce::from_slice(&self.nonce); // 12-byte nonce
        match self.key_size {
            AesKeySize::Aes128 => {
                let cipher = Aes128Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())
            }
            AesKeySize::Aes256 => {
                let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
                cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())
            }
        }
    }
}

#[cfg(feature = "aes")]
impl StreamEncryption for AesGcmEncryption {
    type Error = String;

    fn encrypt_stream<R: Read, W: Write>(
        &self,
        mut input: R,
        mut output: W,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<(), Self::Error> {
        let mut nonce = *<&[u8; 12]>::try_from(nonce).map_err(|_| "Invalid nonce length".to_string())?;
        let mut buffer = vec![0u8; 1024]; // 1KB buffer size
    
        match self.key_size {
            AesKeySize::Aes128 => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
                while let Ok(bytes_read) = input.read(&mut buffer) {
                    if bytes_read == 0 {
                        break;
                    }
                    let encrypted_chunk = cipher
                        .encrypt(Nonce::from_slice(&nonce), &buffer[..bytes_read])
                        .map_err(|e| e.to_string())?; // Convert aes_gcm::Error to String
                    output
                        .write_all(&encrypted_chunk)
                        .map_err(|e| e.to_string())?;
                    Self::increment_nonce(&mut nonce);
                }
            }
            AesKeySize::Aes256 => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
                while let Ok(bytes_read) = input.read(&mut buffer) {
                    if bytes_read == 0 {
                        break;
                    }
                    let encrypted_chunk = cipher
                        .encrypt(Nonce::from_slice(&nonce), &buffer[..bytes_read])
                        .map_err(|e| e.to_string())?; // Convert aes_gcm::Error to String
                    output
                        .write_all(&encrypted_chunk)
                        .map_err(|e| e.to_string())?;
                    Self::increment_nonce(&mut nonce);
                }
            }
        }
    
        buffer.zeroize(); // Zeroize sensitive data
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
        let mut buffer = vec![0u8; 1024]; // 1KB buffer size
    
        match self.key_size {
            AesKeySize::Aes128 => {
                let cipher = Aes128Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
                while let Ok(bytes_read) = input.read(&mut buffer) {
                    if bytes_read == 0 {
                        break;
                    }
                    let decrypted_chunk = cipher
                        .decrypt(Nonce::from_slice(&nonce), &buffer[..bytes_read])
                        .map_err(|e| e.to_string())?; // Convert aes_gcm::Error to String
                    output
                        .write_all(&decrypted_chunk)
                        .map_err(|e| e.to_string())?;
                    Self::increment_nonce(&mut nonce);
                }
            }
            AesKeySize::Aes256 => {
                let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
                while let Ok(bytes_read) = input.read(&mut buffer) {
                    if bytes_read == 0 {
                        break;
                    }
                    let decrypted_chunk = cipher
                        .decrypt(Nonce::from_slice(&nonce), &buffer[..bytes_read])
                        .map_err(|e| e.to_string())?; // Convert aes_gcm::Error to String
                    output
                        .write_all(&decrypted_chunk)
                        .map_err(|e| e.to_string())?;
                    Self::increment_nonce(&mut nonce);
                }
            }
        }
    
        buffer.zeroize(); // Zeroize sensitive data
        Ok(())
    }
}



#[cfg(test)]
#[cfg(feature = "aes")]
mod tests {
    use crate::{SymmetricEncryption, AesGcmEncryption, AesKeySize,StreamEncryption};
    use std::fs::File;
    use std::io::{BufReader, BufWriter, Cursor, Read, Write};
    use tempfile::tempdir;
    const KEY: [u8; 16] = [0u8; 16]; // AES-128 key
    const NONCE: [u8; 12] = [1u8; 12]; // AES nonce

    #[test]
    fn test_aes_gcm_encrypt_decrypt_128() {
        let key = vec![0u8; 16]; // 16 bytes for AES-128
        let nonce = vec![1u8; 12]; // 12 bytes nonce
        let data = b"Hello, AES-128 GCM!".to_vec();

        let aes = AesGcmEncryption::new(AesKeySize::Aes128, key.clone(), nonce.clone())
            .expect("Failed to create AES-GCM instance");

        // Encrypt
        let encrypted = aes.encrypt(&data).expect("Encryption failed");
        assert_ne!(data, encrypted); // Encrypted data should not equal plaintext

        // Decrypt
        let decrypted = aes.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(data, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_aes_gcm_encrypt_decrypt_256() {
        let key = vec![0u8; 32]; // 32 bytes for AES-256
        let nonce = vec![2u8; 12]; // 12 bytes nonce
        let data = b"Hello, AES-256 GCM!".to_vec();

        let aes = AesGcmEncryption::new(AesKeySize::Aes256, key.clone(), nonce.clone())
            .expect("Failed to create AES-GCM instance");

        // Encrypt
        let encrypted = aes.encrypt(&data).expect("Encryption failed");
        assert_ne!(data, encrypted); // Encrypted data should not equal plaintext

        // Decrypt
        let decrypted = aes.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(data, decrypted); // Decrypted data should match original plaintext
    }

    #[test]
    fn test_invalid_key_length() {
        let invalid_key = vec![0u8; 10]; // Invalid key length
        let nonce = vec![0u8; 12]; // Valid nonce

        let result = AesGcmEncryption::new(AesKeySize::Aes128, invalid_key, nonce);
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap(),
            "Invalid key length for Aes128: expected 16, got 10"
        );
    }

    #[test]
    fn test_invalid_nonce_length() {
        let key = vec![0u8; 16]; // Valid key length for AES-128
        let invalid_nonce = vec![0u8; 10]; // Invalid nonce length

        let result = AesGcmEncryption::new(AesKeySize::Aes128, key, invalid_nonce);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap(), "Invalid nonce length: expected 12 bytes.");
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key = vec![0u8; 16]; // Valid key length for AES-128
        let wrong_key = vec![1u8; 16]; // Different key
        let nonce = vec![0u8; 12]; // Valid nonce
        let data = b"Sensitive data!".to_vec();

        let aes_encryptor = AesGcmEncryption::new(AesKeySize::Aes128, key.clone(), nonce.clone())
            .expect("Failed to create AES-GCM instance");
        let aes_decryptor = AesGcmEncryption::new(AesKeySize::Aes128, wrong_key, nonce.clone())
            .expect("Failed to create AES-GCM instance");

        let encrypted = aes_encryptor.encrypt(&data).expect("Encryption failed");
        let result = aes_decryptor.decrypt(&encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_nonce() {
        let key = vec![0u8; 16]; // Valid key length for AES-128
        let nonce = vec![0u8; 12]; // Original nonce
        let wrong_nonce = vec![1u8; 12]; // Different nonce
        let data = b"Sensitive data!".to_vec();

        let aes_encryptor = AesGcmEncryption::new(AesKeySize::Aes128, key.clone(), nonce.clone())
            .expect("Failed to create AES-GCM instance");
        let aes_decryptor = AesGcmEncryption::new(AesKeySize::Aes128, key.clone(), wrong_nonce)
            .expect("Failed to create AES-GCM instance");

        let encrypted = aes_encryptor.encrypt(&data).expect("Encryption failed");
        let result = aes_decryptor.decrypt(&encrypted);

        assert!(result.is_err());
    }

    #[test]
    fn test_encrypt_empty_data() {
        let key = vec![0u8; 16]; // Valid key length for AES-128
        let nonce = vec![0u8; 12]; // Valid nonce
        let data = b"".to_vec(); // Empty data

        let aes = AesGcmEncryption::new(AesKeySize::Aes128, key, nonce)
            .expect("Failed to create AES-GCM instance");

        let encrypted = aes.encrypt(&data).expect("Encryption failed");
        assert!(!encrypted.is_empty());

        let decrypted = aes.decrypt(&encrypted).expect("Decryption failed");
        assert_eq!(data, decrypted); // Decrypted data should match original plaintext
    }




    fn setup_aes() -> AesGcmEncryption {
        AesGcmEncryption::new(AesKeySize::Aes128, KEY.to_vec(), NONCE.to_vec())
            .expect("Failed to create AES instance")
    }

    #[test]
    fn test_stream_encryption_with_memory_streams() {
        let aes = setup_aes();
        let plaintext = b"Hello, Stream Encryption!";

        let mut input = Cursor::new(plaintext.to_vec());
        let mut encrypted_output = Vec::new();

        // Encrypt
        aes.encrypt_stream(&mut input, &mut encrypted_output, &KEY, &NONCE)
            .expect("Encryption failed");

        let mut encrypted_input = Cursor::new(encrypted_output);
        let mut decrypted_output = Vec::new();

        // Decrypt
        aes.decrypt_stream(&mut encrypted_input, &mut decrypted_output, &KEY, &NONCE)
            .expect("Decryption failed");

        assert_eq!(plaintext.to_vec(), decrypted_output);
    }

    #[test]
    fn test_stream_encryption_with_file_streams() {
        let aes = setup_aes();
        let plaintext = b"File-based streaming test.";
        let temp_dir = tempdir().expect("Failed to create temp dir");

        let input_file_path = temp_dir.path().join("plaintext.txt");
        let encrypted_file_path = temp_dir.path().join("encrypted.txt");
        let decrypted_file_path = temp_dir.path().join("decrypted.txt");

        // Write plaintext to a file
        let mut input_file = File::create(&input_file_path).expect("Failed to create input file");
        input_file.write_all(plaintext).expect("Failed to write plaintext");
        input_file.sync_all().expect("Failed to sync input file");

        // Encrypt
        let input_file = File::open(&input_file_path).expect("Failed to open input file");
        let mut encrypted_file =
            File::create(&encrypted_file_path).expect("Failed to create encrypted file");
        aes.encrypt_stream(
            BufReader::new(input_file),
            BufWriter::new(&mut encrypted_file),
            &KEY,
            &NONCE,
        )
        .expect("Encryption failed");

        // Decrypt
        let encrypted_file = File::open(&encrypted_file_path).expect("Failed to open encrypted file");
        let mut decrypted_file =
            File::create(&decrypted_file_path).expect("Failed to create decrypted file");
        aes.decrypt_stream(
            BufReader::new(encrypted_file),
            BufWriter::new(&mut decrypted_file),
            &KEY,
            &NONCE,
        )
        .expect("Decryption failed");

        // Read decrypted content and compare
        let mut decrypted_content = Vec::new();
        let mut decrypted_file =
            File::open(&decrypted_file_path).expect("Failed to open decrypted file");
        decrypted_file
            .read_to_end(&mut decrypted_content)
            .expect("Failed to read decrypted file");

        assert_eq!(plaintext.to_vec(), decrypted_content);
    }
    
    #[test]
    fn test_empty_stream() {
        let aes = setup_aes();

        let mut input = Cursor::new(Vec::new());
        let mut encrypted_output = Vec::new();

        // Encrypt
        aes.encrypt_stream(&mut input, &mut encrypted_output, &KEY, &NONCE)
            .expect("Encryption failed");

        assert!(encrypted_output.is_empty(), "Encrypted output should be empty");

        let mut encrypted_input = Cursor::new(encrypted_output);
        let mut decrypted_output = Vec::new();

        // Decrypt
        aes.decrypt_stream(&mut encrypted_input, &mut decrypted_output, &KEY, &NONCE)
            .expect("Decryption failed");

        assert!(decrypted_output.is_empty(), "Decrypted output should be empty");
    }

}


