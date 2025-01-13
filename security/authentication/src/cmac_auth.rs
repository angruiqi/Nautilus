// security\authentication\src\cmac_auth.rs
use aes::Aes256;
use cmac::{Cmac, Mac};
use crate::traits::MessageAuthentication;

type CmacAes256 = Cmac<Aes256>;

pub struct CmacAuthentication {
    key: Vec<u8>,
}

impl CmacAuthentication {
  pub fn new(key: &[u8]) -> Self {
    println!("Key length: {}", key.len()); // Debugging print statement
    assert_eq!(key.len(), 32, "Key must be 32 bytes long for AES-256");
    Self { key: key.to_vec() }
}
}

impl MessageAuthentication for CmacAuthentication {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut mac = CmacAes256::new_from_slice(&self.key).expect("Valid key size");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let mut mac = CmacAes256::new_from_slice(&self.key).expect("Valid key size");
        mac.update(message);
        mac.verify_slice(signature).is_ok()
    }
}
