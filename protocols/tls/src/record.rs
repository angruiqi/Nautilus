// protocols\tls\src\record.rs
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use std::error::Error;
use rand::Rng;

#[derive(Debug)]
pub enum RecordType {
    Handshake,
    ApplicationData,
}
#[derive(Debug)]
pub struct TlsRecord {
    record_type: RecordType,
    payload: Vec<u8>,
}

impl TlsRecord {
    pub fn new(record_type: RecordType, payload: Vec<u8>) -> Self {
        Self { record_type, payload }
    }

    pub fn encrypt(&mut self, key: &[u8]) -> Result<(), RecordError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce_bytes: [u8; 12] = rand::thread_rng().gen(); // Generate random 12-byte nonce
        let nonce = Nonce::from_slice(&nonce_bytes);
    
        self.payload = cipher
            .encrypt(nonce, self.payload.as_ref())
            .map_err(|_| RecordError::EncryptionError)?;
        self.payload.splice(0..0, nonce_bytes.iter().cloned()); // Prepend nonce to payload
        Ok(())
    }
    pub fn decrypt(&mut self, key: &[u8]) -> Result<Vec<u8>, RecordError> {
        if self.payload.len() < 12 {
            return Err(RecordError::DecryptionError); // Not enough data for nonce
        }
    
        let (nonce_bytes, ciphertext) = self.payload.split_at(12); // Extract nonce
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let nonce = Nonce::from_slice(nonce_bytes);
    
        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| RecordError::DecryptionError)
    }
    pub fn serialize(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.push(match self.record_type {
            RecordType::Handshake => 0x01,
            RecordType::ApplicationData => 0x02,
        });
        data.extend(&self.payload);
        data
    }
    pub fn deserialize(data: &[u8]) -> Result<Self, RecordError> {
        if data.is_empty() {
            eprintln!("[ERROR] Received empty data.");
            return Err(RecordError::InvalidRecord);
        }
    
        let record_type = match data[0] {
            0x01 => RecordType::Handshake,
            0x02 => RecordType::ApplicationData,
            _ => {
                eprintln!("[ERROR] Invalid record type: {}", data[0]);
                return Err(RecordError::InvalidRecord);
            }
        };
        
        let payload = data[1..].to_vec();
        println!("[DEBUG] Received record type: {:?}, Payload length: {}", record_type, payload.len());
        
        Ok(Self { record_type, payload })
    }
}

#[derive(Debug)]
pub enum RecordError {
    EncryptionError,
    DecryptionError,
    InvalidRecord,
    WriteError,
    ReadError,
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl Error for RecordError {}