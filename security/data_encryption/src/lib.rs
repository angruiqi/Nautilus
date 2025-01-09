// security\data_encryption\src\lib.rs
// ================================================ Encryption Traits Interface ==============================================
mod encryption_trait;
pub use encryption_trait::SymmetricEncryption;

mod encryption_error;
pub use encryption_error::EncryptionError;

mod key_derivation_trait;
pub use key_derivation_trait::KeyDerivation;

mod stream_encryption_trait;
pub use stream_encryption_trait::StreamEncryption;
// ================================================= Encryption Public API Interface =========================================
mod encryption;
pub use encryption::*;


// ================================================= Key Derivations API Interface ============================================
mod key_derive;
pub use key_derive::*;


// ================================================ Misc. && Utilities API Interface ===========================================
mod utils; // utility Services are both private/public

// =============================================================== FIN =========================================================