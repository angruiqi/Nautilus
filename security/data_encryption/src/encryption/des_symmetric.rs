// ================================ Data Encryption Module =======================
// security\data_encryption\src\encryption\des_symmetric.rs
#[cfg(feature = "3des")]
use des::cipher::{BlockEncrypt, BlockDecrypt, KeyInit, generic_array::GenericArray};
#[cfg(feature = "3des")]
use des::TdesEde3;
#[cfg(feature = "3des")]
use hmac::{Hmac, Mac};
#[cfg(feature = "3des")]
use sha2::Sha256;
#[cfg(feature = "3des")]
use crate::{SymmetricEncryption, StreamEncryption};
#[cfg(feature = "3des")]
use std::io::{Read, Write};

// ========================= DesEncryption Struct =========================
#[cfg(feature = "3des")]
pub struct DesEncryption {
    key: Vec<u8>,
}

#[cfg(feature = "3des")]
impl DesEncryption {
    pub fn new(key: Vec<u8>) -> Result<Self, String> {
        if key.len() != 24 {
            return Err("Invalid key length: Triple DES requires a 24-byte key.".to_string());
        }
        Ok(Self { key })
    }

    fn increment_nonce(nonce: &mut [u8; 8]) {
        for byte in nonce.iter_mut().rev() {
            *byte = byte.wrapping_add(1);
            if *byte != 0 {
                break;
            }
        }
    }
}

// ========================= HMAC Calculation =========================
#[cfg(feature = "3des")]
fn calculate_hmac(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

// ========================= SymmetricEncryption Trait =========================
#[cfg(feature = "3des")]
impl SymmetricEncryption for DesEncryption {
    type Error = String;

    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let cipher = TdesEde3::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        let mut result = Vec::new();

        let mut padded_plaintext = plaintext.to_vec();
        let padding_len = 8 - (padded_plaintext.len() % 8);
        padded_plaintext.extend(vec![padding_len as u8; padding_len]);

        for chunk in padded_plaintext.chunks(8) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            result.extend_from_slice(&block);
        }

        let hmac = calculate_hmac(&self.key, &result);
        result.extend_from_slice(&hmac);

        Ok(result)
    }

    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Self::Error> {
        if ciphertext.len() < 32 {
            return Err("Ciphertext too short to contain valid HMAC.".to_string());
        }

        // Split the ciphertext and the HMAC
        let (ciphertext_body, hmac) = ciphertext.split_at(ciphertext.len() - 32);

        let cipher = TdesEde3::new_from_slice(&self.key).map_err(|e| e.to_string())?;
        let mut result = Vec::new();

        // Process ciphertext in 8-byte chunks
        for chunk in ciphertext_body.chunks(8) {
            let mut block = GenericArray::clone_from_slice(chunk);
            cipher.decrypt_block(&mut block);
            result.extend_from_slice(&block);
        }

        // Remove padding first
        if let Some(&padding_len) = result.last() {
            let padding_len = padding_len as usize;
            if padding_len == 0 || padding_len > 8 || result.len() < padding_len {
                return Err("Invalid padding detected".to_string());
            }

            let padding_start = result.len() - padding_len;
            if !result[padding_start..].iter().all(|&byte| byte as usize == padding_len) {
                return Err("Invalid padding detected".to_string());
            }

            result.truncate(result.len() - padding_len);
        } else {
            return Err("Invalid padding: ciphertext is empty".to_string());
        }

        // Verify HMAC after successful padding validation
        let calculated_hmac = calculate_hmac(&self.key, ciphertext_body);
        if calculated_hmac != hmac {
            return Err("Decryption integrity check failed. Likely wrong key.".to_string());
        }

        Ok(result)
    }
}

// ========================= StreamEncryption Trait =========================
#[cfg(feature = "3des")]
impl StreamEncryption for DesEncryption {
    type Error = String;

    fn encrypt_stream<R: Read, W: Write>(
        &self,
        mut input: R,
        mut output: W,
        key: &[u8],
        nonce: &[u8],
    ) -> Result<(), Self::Error> {
        let mut nonce = *<&[u8; 8]>::try_from(nonce).map_err(|_| "Invalid nonce length".to_string())?;
        let cipher = TdesEde3::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; 1024];

        while let Ok(bytes_read) = input.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }

            let mut encrypted_chunk = Vec::new();
            for chunk in buffer[..bytes_read].chunks(8) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.encrypt_block(&mut block);
                encrypted_chunk.extend_from_slice(&block);
            }

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
        let mut nonce = *<&[u8; 8]>::try_from(nonce).map_err(|_| "Invalid nonce length".to_string())?;
        let cipher = TdesEde3::new_from_slice(key).map_err(|e| e.to_string())?;
        let mut buffer = vec![0u8; 1024];

        while let Ok(bytes_read) = input.read(&mut buffer) {
            if bytes_read == 0 {
                break;
            }

            let mut decrypted_chunk = Vec::new();
            for chunk in buffer[..bytes_read].chunks(8) {
                let mut block = GenericArray::clone_from_slice(chunk);
                cipher.decrypt_block(&mut block);
                decrypted_chunk.extend_from_slice(&block);
            }

            output.write_all(&decrypted_chunk).map_err(|e| e.to_string())?;
            Self::increment_nonce(&mut nonce);
        }

        Ok(())
    }
}

// ============================================================================
