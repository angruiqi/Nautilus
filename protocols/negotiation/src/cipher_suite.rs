use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
    EcdhNistP256AesGcm,
    Custom(String), // Allow extensibility
}

impl CipherSuite {
    pub fn name(&self) -> String {
        match self {
            CipherSuite::Aes256GcmSha384 => "AES-256-GCM-SHA384".to_string(),
            CipherSuite::ChaCha20Poly1305Sha256 => "ChaCha20-Poly1305-SHA256".to_string(),
            CipherSuite::EcdhNistP256AesGcm => "ECDH-NISTP256-AES-GCM".to_string(),
            CipherSuite::Custom(name) => name.clone(),
        }
    }
}