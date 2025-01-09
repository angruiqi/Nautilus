// identity\key-storage\src\key_storage_error.rs
#[derive(Debug)]
pub enum KeyStorageError {
    SaveError(String),
    LoadError(String),
    RemoveError(String),
    EncryptionError(String),
    BackendError(String),
    NotSupported(String),
    Unknown(String),
    FileError(String),
    SerializationError(String),
}