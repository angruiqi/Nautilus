// identity\key-storage\src\key_storage_error.rs
//? **Key Storage Error Enum**
//?
//? Defines error variants for key storage operations, providing a structured way to handle
//? errors that may occur during key management.

/// Represents various errors that can occur in key storage operations.
#[derive(Debug)]
pub enum KeyStorageError {
    /// Error when saving a key.
    SaveError(String),
    /// Error when loading a key.
    LoadError(String),
    /// Error when removing a key.
    RemoveError(String),
    /// Error during encryption or decryption.
    EncryptionError(String),
    /// Error related to the storage backend.
    BackendError(String),
    /// Indicates an unsupported operation or feature.
    NotSupported(String),
    /// Unknown or unexpected error.
    Unknown(String),
    /// Error related to file operations.
    FileError(String),
    /// Error during serialization or deserialization.
    SerializationError(String),
}