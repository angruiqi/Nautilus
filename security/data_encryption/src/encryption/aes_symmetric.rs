// ================================ Data Encryption Module =======================
// security\data_encryption\src\encryption\aes_symmetric.rs
use crate::{SymmetricEncryption, StreamEncryption};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use std::io::{Read, Write};
use zeroize::Zeroize;

// ========================= Aes256GcmEncryption Struct =========================
#[derive(Clone,Debug)]
pub struct Aes256GcmEncryption {
    key: Vec<u8>,
    nonce: Vec<u8>,
}

impl Drop for Aes256GcmEncryption {
    fn drop(&mut self) {
        self.key.zeroize();
        self.nonce.zeroize();
    }
}

impl Aes256GcmEncryption {
    /// Creates a new `Aes256GcmEncryption` instance.
    pub fn new(key: Vec<u8>, nonce: Vec<u8>) -> Result<Self, String> {
        if key.len() != 32 {
            return Err(format!("Invalid key length: expected 32 bytes, got {}", key.len()));
        }

        if nonce.len() != 12 {
            return Err("Invalid nonce length: expected 12 bytes.".to_string());
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

// ========================= SymmetricEncryption Trait =========================
impl SymmetricEncryption for Aes256GcmEncryption {
    type Error = String;

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let nonce = Nonce::from_slice(&self.nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let nonce = Nonce::from_slice(&self.nonce);
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())
    }
}

// ========================= StreamEncryption Trait =========================
impl StreamEncryption for Aes256GcmEncryption {
    type Error = String;

    fn encrypt_stream<R: Read, W: Write>(
        &self,
        mut input: R,
        mut output: W,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<(), Self::Error> {
        let mut nonce = *<&[u8; 12]>::try_from(nonce).map_err(|_| "Invalid nonce length".to_string())?;
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; 1024];

        while let Ok(bytes_read) = input.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }

            let encrypted_chunk = cipher
                .encrypt(Nonce::from_slice(&nonce), &buffer[..bytes_read])
                .map_err(|e| e.to_string())?;
            output.write_all(&encrypted_chunk).map_err(|e| e.to_string())?;
            Self::increment_nonce(&mut nonce);
        }

        buffer.zeroize();
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
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; 1024];

        while let Ok(bytes_read) = input.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }

            let decrypted_chunk = cipher
                .decrypt(Nonce::from_slice(&nonce), &buffer[..bytes_read])
                .map_err(|e| e.to_string())?;
            output.write_all(&decrypted_chunk).map_err(|e| e.to_string())?;
            Self::increment_nonce(&mut nonce);
        }

        buffer.zeroize();
        Ok(())
    }
}

// ============================================================================
impl Aes256GcmEncryption {
    // Encrypt the given plaintext using the provided session key
    pub fn encrypt_with_key(&self, plaintext: &[u8], session_key: &[u8]) -> Result<Vec<u8>, String> {
        // Use the provided session key for encryption
        let cipher = Aes256Gcm::new_from_slice(session_key).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(&self.nonce);
        cipher.encrypt(nonce, plaintext).map_err(|e| e.to_string())
    }

    // Decrypt the given ciphertext using the provided session key
    pub fn decrypt_with_key(&self, ciphertext: &[u8], session_key: &[u8]) -> Result<Vec<u8>, String> {
        // Use the provided session key for decryption
        let cipher = Aes256Gcm::new_from_slice(session_key).map_err(|e| e.to_string())?;
        let nonce = Nonce::from_slice(&self.nonce);
        cipher.decrypt(nonce, ciphertext).map_err(|e| e.to_string())
    }
}