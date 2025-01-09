// security\data_encryption\encryption_error.rs
#[derive(Debug)]
pub enum EncryptionError {
    EncryptionFailed(String),
    DecryptionFailed(String),
    KeyGenerationFailed(String),
    InvalidKey(String),
    Other(String),
}