use crate::tls_error::TLSError;
use negotiation::CipherSuite;
use data_encryption::{SymmetricEncryption, AesGcmEncryption, AesKeySize};

pub fn init_encryption(
    suite: &CipherSuite,
    key_bytes: &[u8],
    nonce_bytes: &[u8],
) -> Result<Box<dyn SymmetricEncryption<Error=String> + Send + Sync>, TLSError> {
    match suite {
        CipherSuite::Aes256GcmSha384 => {
            if key_bytes.len() != 32 {
                return Err(TLSError::Other("Expected 32-byte key for AES-256".into()));
            }
            if nonce_bytes.len() != 12 {
                return Err(TLSError::Other("Expected 12-byte nonce for AES-GCM".into()));
            }
            let aes = AesGcmEncryption::new(
                AesKeySize::Aes256,
                key_bytes.to_vec(),
                nonce_bytes.to_vec(),
            ).map_err(|e| TLSError::Other(format!("AES init error: {}", e)))?;
            Ok(Box::new(aes))
        },
        // Catch-all or handle the other variants:
        // e.g. CipherSuite::ChaCha20Poly1305Sha256, etc.
        _ => Err(TLSError::Other("Cipher suite not implemented".into())),
    }
}
