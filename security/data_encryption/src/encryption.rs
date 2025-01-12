// security\data_encryption\src\encryption.rs
#[cfg(feature = "aes")]
mod aes_symmetric;
#[cfg(feature = "aes")]
pub use aes_symmetric::Aes256GcmEncryption;



#[cfg(feature = "blwfish")]
mod blowfish_symmetric;
#[cfg(feature = "blwfish")]
pub use blowfish_symmetric::BlowfishEncryption;


#[cfg(feature = "chacha20")]
mod chacha20_symmetric;
#[cfg(feature = "chacha20")]
pub use chacha20_symmetric::ChaCha20Encryption;


#[cfg(feature = "3des")]
mod des_symmetric;
#[cfg(feature = "3des")]
pub use des_symmetric::DesEncryption;


/// Enum representing supported symmetric cipher suites.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SymmetricCipherSuite {
    /// AES-256-GCM (Advanced Encryption Standard)
    #[cfg(feature = "aes")]
    AES256GCM { priority: u8 },

    /// Blowfish (Legacy symmetric encryption)
    #[cfg(feature = "blowfish")]
    Blowfish { priority: u8 },

    /// ChaCha20-Poly1305 (High-speed encryption)
    #[cfg(feature = "chacha20")]
    ChaCha20 { priority: u8 },

    /// Triple DES (Legacy symmetric encryption)
    #[cfg(feature = "3des")]
    TripleDES { priority: u8 },

    /// Custom cipher suite for advanced or experimental use cases.
    Custom { name: String, priority: u8 },
}

impl SymmetricCipherSuite {
    /// Returns a human-readable name for the cipher suite.
    pub fn name(&self) -> String {
        match self {
            #[cfg(feature = "aes")]
            SymmetricCipherSuite::AES256GCM { .. } => "AES256-GCM".to_string(),
            #[cfg(feature = "blowfish")]
            SymmetricCipherSuite::Blowfish { .. } => "Blowfish".to_string(),
            #[cfg(feature = "chacha20")]
            SymmetricCipherSuite::ChaCha20 { .. } => "ChaCha20".to_string(),
            #[cfg(feature = "3des")]
            SymmetricCipherSuite::TripleDES { .. } => "TripleDES".to_string(),
            SymmetricCipherSuite::Custom { name, .. } => name.clone(),
        }
    }

    /// Checks if the cipher suite is supported (based on features).
    pub fn is_supported(&self) -> bool {
        match self {
            #[cfg(feature = "aes")]
            SymmetricCipherSuite::AES256GCM { .. } => true,
            #[cfg(feature = "blowfish")]
            SymmetricCipherSuite::Blowfish { .. } => true,
            #[cfg(feature = "chacha20")]
            SymmetricCipherSuite::ChaCha20 { .. } => true,
            #[cfg(feature = "3des")]
            SymmetricCipherSuite::TripleDES { .. } => true,
            SymmetricCipherSuite::Custom { .. } => true,
        }
    }

    /// Returns a list of supported cipher suites.
    pub fn supported_suites() -> Vec<String> {
        let mut suites = vec![];

        #[cfg(feature = "aes")]
        suites.push("AES256-GCM".to_string());

        #[cfg(feature = "blowfish")]
        suites.push("Blowfish".to_string());

        #[cfg(feature = "chacha20")]
        suites.push("ChaCha20".to_string());

        #[cfg(feature = "3des")]
        suites.push("TripleDES".to_string());

        suites
    }

    /// Returns the key size (in bytes) required for the cipher suite.
    pub fn key_size(&self) -> usize {
        match self {
            #[cfg(feature = "aes")]
            SymmetricCipherSuite::AES256GCM { .. } => 32, // 256-bit key

            #[cfg(feature = "blowfish")]
            SymmetricCipherSuite::Blowfish { .. } => 16, // Minimum 128-bit key (can vary from 4 to 56 bytes)

            #[cfg(feature = "chacha20")]
            SymmetricCipherSuite::ChaCha20 { .. } => 32, // 256-bit key

            #[cfg(feature = "3des")]
            SymmetricCipherSuite::TripleDES { .. } => 24, // 192-bit key

            SymmetricCipherSuite::Custom { .. } => {
                panic!("Custom cipher suites must define their key size separately.");
            }
        }
    }

    /// Returns the nonce size (in bytes) required for the cipher suite.
    pub fn nonce_size(&self) -> usize {
        match self {
            #[cfg(feature = "aes")]
            SymmetricCipherSuite::AES256GCM { .. } => 12, // 96-bit nonce

            #[cfg(feature = "blowfish")]
            SymmetricCipherSuite::Blowfish { .. } => 0, // Blowfish doesn't require a nonce

            #[cfg(feature = "chacha20")]
            SymmetricCipherSuite::ChaCha20 { .. } => 12, // 96-bit nonce

            #[cfg(feature = "3des")]
            SymmetricCipherSuite::TripleDES { .. } => 8, // 64-bit IV

            SymmetricCipherSuite::Custom { .. } => {
                panic!("Custom cipher suites must define their nonce size separately.");
            }
        }
    }
}
