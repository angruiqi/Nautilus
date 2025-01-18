use identity::{PKITraits, PKIError};

#[cfg(feature = "pki_rsa")]
use identity::RSAkeyPair;

#[cfg(feature = "dilithium")]
use identity::DilithiumKeyPair;

#[cfg(feature = "falcon")]
use identity::FalconKeyPair;

#[cfg(feature = "ed25519")]
use identity::Ed25519KeyPair;

use crate::IdentityError;
use std::fmt;

#[derive(Clone, Debug)]
pub enum Algorithm {
    #[cfg(feature = "pki_rsa")]
    RSA,

    #[cfg(feature = "dilithium")]
    Dilithium,

    #[cfg(feature = "falcon")]
    Falcon,

    #[cfg(feature = "ed25519")]
    Ed25519,
}

pub enum PKI {
    #[cfg(feature = "pki_rsa")]
    RSA(RSAkeyPair),

    #[cfg(feature = "dilithium")]
    Dilithium(DilithiumKeyPair),

    #[cfg(feature = "falcon")]
    Falcon(FalconKeyPair),

    #[cfg(feature = "ed25519")]
    Ed25519(Ed25519KeyPair),
}
impl PKI {
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, PKIError> {
        match self {
            #[cfg(feature = "pki_rsa")]
            PKI::RSA(rsa) => rsa.sign(data),

            #[cfg(feature = "dilithium")]
            PKI::Dilithium(dilithium) => dilithium.sign(data),

            #[cfg(feature = "falcon")]
            PKI::Falcon(falcon) => falcon.sign(data),

            #[cfg(feature = "ed25519")]
            PKI::Ed25519(ed25519) => ed25519.sign(data),

            #[allow(unreachable_patterns)]
            _ => Err(PKIError::UnsupportedOperation("Algorithm not available".to_string())),
        }
    }

    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, PKIError> {
        match self {
            #[cfg(feature = "pki_rsa")]
            PKI::RSA(rsa) => rsa.verify(data, signature),

            #[cfg(feature = "dilithium")]
            PKI::Dilithium(dilithium) => dilithium.verify(data, signature),

            #[cfg(feature = "falcon")]
            PKI::Falcon(falcon) => falcon.verify(data, signature),

            #[cfg(feature = "ed25519")]
            PKI::Ed25519(ed25519) => ed25519.verify(data, signature),

            #[allow(unreachable_patterns)]
            _ => Err(PKIError::UnsupportedOperation("Algorithm not available".to_string())),
        }
    }

    pub fn public_key_raw_bytes(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "pki_rsa")]
            PKI::RSA(rsa) => rsa.get_public_key_raw_bytes(),

            #[cfg(feature = "dilithium")]
            PKI::Dilithium(dilithium) => dilithium.get_public_key_raw_bytes(),

            #[cfg(feature = "falcon")]
            PKI::Falcon(falcon) => falcon.get_public_key_raw_bytes(),

            #[cfg(feature = "ed25519")]
            PKI::Ed25519(ed25519) => ed25519.get_public_key_raw_bytes(),

            #[allow(unreachable_patterns)]
            _ => Vec::new(), // Return an empty vector if the algorithm is not available
        }
    }

    pub fn key_type(&self) -> String {
        match self {
            #[cfg(feature = "pki_rsa")]
            PKI::RSA(_) => RSAkeyPair::key_type(),

            #[cfg(feature = "dilithium")]
            PKI::Dilithium(_) => DilithiumKeyPair::key_type(),

            #[cfg(feature = "falcon")]
            PKI::Falcon(_) => FalconKeyPair::key_type(),

            #[cfg(feature = "ed25519")]
            PKI::Ed25519(_) => Ed25519KeyPair::key_type(),

            #[allow(unreachable_patterns)]
            _ => "Unsupported".to_string(), // Fallback for unsupported algorithms
        }
    }
}

impl PKI {
    pub fn private_key_raw_bytes(&self) -> Vec<u8> {
        match self {
            #[cfg(feature = "pki_rsa")]
            PKI::RSA(rsa_keypair) => rsa_keypair.private_key_raw_bytes(),
    
            #[cfg(feature = "dilithium")]
            PKI::Dilithium(_) => {
                // Handle Dilithium-specific behavior if needed
                vec![]
            },
    
            #[cfg(feature = "falcon")]
            PKI::Falcon(_) => {
                // Handle Falcon-specific behavior if needed
                vec![]
            },
    
            #[cfg(feature = "ed25519")]
            PKI::Ed25519(_) => {
                // Handle Ed25519-specific behavior if needed
                vec![]
            },
    
            // Fallback for any unsupported or excluded variants
            #[cfg(not(any(feature = "pki_rsa", feature = "dilithium", feature = "falcon", feature = "ed25519")))]
            _ => vec![], // Return empty vector or handle unsupported case
        }
    }
}

// Ensure the PKI::RSA (or other types) implement Clone
impl Clone for PKI {
    fn clone(&self) -> Self {
        match self {
            #[cfg(feature = "pki_rsa")]
            PKI::RSA(rsa_keypair) => PKI::RSA(rsa_keypair.clone()),

            #[cfg(feature = "dilithium")]
            PKI::Dilithium(dilithium_keypair) => PKI::Dilithium(dilithium_keypair.clone()),

            #[cfg(feature = "falcon")]
            PKI::Falcon(falcon_keypair) => PKI::Falcon(falcon_keypair.clone()),

            #[cfg(feature = "ed25519")]
            PKI::Ed25519(ed25519_keypair) => PKI::Ed25519(ed25519_keypair.clone()),

            #[cfg(not(any(feature = "pki_rsa", feature = "dilithium", feature = "falcon", feature = "ed25519")))]
            _ => panic!("Cloning unsupported for this PKI type"),
        }
    }
}
pub struct PKIFactory;

impl PKIFactory {
    pub fn create_pki(algorithm: Algorithm) -> Result<PKI, IdentityError> {
        match algorithm {
            #[cfg(feature = "pki_rsa")]
            Algorithm::RSA => {
                let rsa = RSAkeyPair::generate_key_pair()
                    .map_err(|e| IdentityError::Other(format!("RSA key pair generation failed: {}", e)))?;
                Ok(PKI::RSA(rsa))
            }

            #[cfg(feature = "dilithium")]
            Algorithm::Dilithium => {
                let dilithium = DilithiumKeyPair::generate_key_pair()
                    .map_err(|e| IdentityError::Other(format!("Dilithium key pair generation failed: {}", e)))?;
                Ok(PKI::Dilithium(dilithium))
            }

            #[cfg(feature = "falcon")]
            Algorithm::Falcon => {
                let falcon = FalconKeyPair::generate_key_pair()
                    .map_err(|e| IdentityError::Other(format!("Falcon key pair generation failed: {}", e)))?;
                Ok(PKI::Falcon(falcon))
            }

            #[cfg(feature = "ed25519")]
            Algorithm::Ed25519 => {
                let ed25519 = Ed25519KeyPair::generate_key_pair()
                    .map_err(|e| IdentityError::Other(format!("Ed25519 key pair generation failed: {}", e)))?;
                Ok(PKI::Ed25519(ed25519))
            }
            #[cfg(not(any(feature = "pki_rsa", feature = "dilithium", feature = "falcon", feature = "ed25519")))]
            _ => Err(IdentityError::Other("Unsupported algorithm".to_string())),
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let algo_name = match self {
            #[cfg(feature = "pki_rsa")]
            Algorithm::RSA => "RSA",

            #[cfg(feature = "dilithium")]
            Algorithm::Dilithium => "Dilithium",

            #[cfg(feature = "falcon")]
            Algorithm::Falcon => "Falcon",

            #[cfg(feature = "ed25519")]
            Algorithm::Ed25519 => "Ed25519",

            #[allow(unreachable_patterns)]
            _ => "Unknown",
        };
        write!(f, "{}", algo_name)
    }
}