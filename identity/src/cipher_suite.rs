// identity\src\cipher_suite.rs
/// Enum representing supported cipher suites in the Nautilus Handshake Protocol.
use serde::{Serialize,Deserialize};
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum CipherSuite {
    /// RSA (PKI-based Signature Scheme)
    #[cfg(feature = "pki_rsa")]
    RSA { priority: u8 },

    /// SECP256K1 (ECDSA-based Signature Scheme)
    #[cfg(feature = "secp256k1")]
    SECP256K1 { priority: u8 },

    /// ECDSA (Elliptic Curve Digital Signature Algorithm)
    #[cfg(feature = "ecdsa")]
    ECDSA { priority: u8 },

    /// Ed25519 (EdDSA over Curve25519)
    #[cfg(feature = "ed25519")]
    Ed25519 { priority: u8 },

    /// Dilithium (Post-Quantum Digital Signature Scheme)
    #[cfg(feature = "dilithium")]
    Dilithium { priority: u8 },

    /// SPHINCS+ (Stateless Hash-based Digital Signature Scheme)
    #[cfg(feature = "spincs")]
    SPHINCSPlus { priority: u8 },

    /// Falcon (Post-Quantum Digital Signature Scheme)
    #[cfg(feature = "falcon")]
    Falcon { priority: u8 },

    /// Kyber (Post-Quantum Key Encapsulation Mechanism)
    #[cfg(feature = "kyber")]
    Kyber { priority: u8 },

    /// Custom cipher suite for advanced or experimental use cases.
    Custom { name: String, priority: u8 },
}

impl CipherSuite {
    /// Returns a human-readable name for the cipher suite.
    pub fn name(&self) -> String {
        match self {
            #[cfg(feature = "pki_rsa")]
            CipherSuite::RSA { .. } => "RSA".to_string(),
            #[cfg(feature = "secp256k1")]
            CipherSuite::SECP256K1 { .. } => "SECP256K1".to_string(),
            #[cfg(feature = "ecdsa")]
            CipherSuite::ECDSA { .. } => "ECDSA".to_string(),
            #[cfg(feature = "ed25519")]
            CipherSuite::Ed25519 { .. } => "Ed25519".to_string(),
            #[cfg(feature = "dilithium")]
            CipherSuite::Dilithium { .. } => "Dilithium".to_string(),
            #[cfg(feature = "spincs")]
            CipherSuite::SPHINCSPlus { .. } => "SPHINCSPlus".to_string(),
            #[cfg(feature = "falcon")]
            CipherSuite::Falcon { .. } => "Falcon".to_string(),
            #[cfg(feature = "kyber")]
            CipherSuite::Kyber { .. } => "Kyber".to_string(),
            CipherSuite::Custom { name, .. } => name.clone(),
        }
    }

    /// Checks if the cipher suite is supported (based on features).
    pub fn is_supported(&self) -> bool {
        match self {
            #[cfg(feature = "pki_rsa")]
            CipherSuite::RSA { .. } => true,
            #[cfg(feature = "secp256k1")]
            CipherSuite::SECP256K1 { .. } => true,
            #[cfg(feature = "ecdsa")]
            CipherSuite::ECDSA { .. } => true,
            #[cfg(feature = "ed25519")]
            CipherSuite::Ed25519 { .. } => true,
            #[cfg(feature = "dilithium")]
            CipherSuite::Dilithium { .. } => true,
            #[cfg(feature = "spincs")]
            CipherSuite::SPHINCSPlus { .. } => true,
            #[cfg(feature = "falcon")]
            CipherSuite::Falcon { .. } => true,
            #[cfg(feature = "kyber")]
            CipherSuite::Kyber { .. } => true,
            CipherSuite::Custom { .. } => true,
        }
    }

    /// Returns a list of supported Signature/Verification schemes.
    pub fn supported_signature_schemes() -> Vec<String> {
        #[allow(unused_mut)]
        let mut schemes = vec![];

        #[cfg(feature = "pki_rsa")]
        schemes.push("RSA".to_string());

        #[cfg(feature = "secp256k1")]
        schemes.push("SECP256K1".to_string());

        #[cfg(feature = "ecdsa")]
        schemes.push("ECDSA".to_string());

        #[cfg(feature = "ed25519")]
        schemes.push("Ed25519".to_string());

        #[cfg(feature = "dilithium")]
        schemes.push("Dilithium".to_string());

        #[cfg(feature = "spincs")]
        schemes.push("SPHINCSPlus".to_string());

        #[cfg(feature = "falcon")]
        schemes.push("Falcon".to_string());

        schemes
    }

    /// Returns a list of supported Key Encapsulation Mechanisms (KEMs).
    pub fn supported_kem_schemes() -> Vec<String> {
        #[allow(unused_mut)]
        let mut schemes = vec![];

        #[cfg(feature = "kyber")]
        schemes.push("Kyber".to_string());

        schemes
    }
}
