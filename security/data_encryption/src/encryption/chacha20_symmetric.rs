// ================================ Data Encryption Module =======================
// security\data_encryption\src\encryption\chacha20_symmetric.rs
#[cfg(feature = "chacha20")]
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
#[cfg(feature = "chacha20")]
use crate::{SymmetricEncryption, StreamEncryption};
#[cfg(feature = "chacha20")]
use std::io::{Read, Write};

// ========================= ChaCha20Encryption Struct =========================
#[cfg(feature = "chacha20")]
#[derive(Clone,Debug)]
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

// ========================= SymmetricEncryption Trait =========================
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

// ========================= StreamEncryption Trait =========================
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

// ============================================================================
