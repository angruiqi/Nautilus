// security\authentication\src\hmac_auth.rs
use hmac::{Hmac, Mac};
use sha2::Sha256;
use crate::traits::MessageAuthentication;

type HmacSha256 = Hmac<Sha256>;

pub struct HmacAuthentication {
    key: Vec<u8>,
}

impl HmacAuthentication {
    pub fn new(key: &[u8]) -> Self {
        Self { key: key.to_vec() }
    }
}

impl MessageAuthentication for HmacAuthentication {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC can take a key of any size");
        mac.update(message);
        mac.finalize().into_bytes().to_vec()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let mut mac = HmacSha256::new_from_slice(&self.key).expect("HMAC can take a key of any size");
        mac.update(message);
        mac.verify_slice(signature).is_ok()
    }
}
