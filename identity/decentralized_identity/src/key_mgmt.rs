// identity\decentralized_identity\src\key_mgmt.rs
use std::collections::HashMap;
use crate::{PKI, IdentityError};

pub struct KeyManager {
    private_keys: HashMap<String, PKI>, // Map key ID to private key (PKI)
    public_keys: HashMap<String, Vec<u8>>, // Map key ID to public key bytes
}

impl KeyManager {
    pub fn new() -> Self {
        KeyManager {
            private_keys: HashMap::new(),
            public_keys: HashMap::new(),
        }
    }

    pub fn add_key(&mut self, key_id: String, pki: PKI) -> Result<(), IdentityError> {
        let public_key = pki.public_key_raw_bytes();
        self.private_keys.insert(key_id.clone(), pki);
        self.public_keys.insert(key_id, public_key);
        Ok(())
    }

    pub fn get_private_key(&self, key_id: &str) -> Result<&PKI, IdentityError> {
        self.private_keys
            .get(key_id)
            .ok_or_else(|| IdentityError::Other(format!("Private key not found for key ID: {}", key_id)))
    }

    pub fn get_public_key(&self, key_id: &str) -> Result<&[u8], IdentityError> {
        self.public_keys
            .get(key_id)
            .map(|key| key.as_slice())
            .ok_or_else(|| IdentityError::Other(format!("Public key not found for key ID: {}", key_id)))
    }
}