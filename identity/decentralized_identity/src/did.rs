use crate::{Algorithm, IdentityError, KeyManager, PKIFactory, PKI};
use base64::engine::general_purpose;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid; // For encoding

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyType {
    #[cfg(feature = "pki_rsa")]
    Rsa,
    #[cfg(feature = "dilithium")]
    Dilithium,
    #[cfg(feature = "falcon")]
    Falcon,
    #[cfg(feature = "ed25519")]
    Ed25519,
    Other(String),
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "pki_rsa")]
            KeyType::Rsa => write!(f, "Rsa"),
            #[cfg(feature = "dilithium")]
            KeyType::Dilithium => write!(f, "Dilithium"),
            #[cfg(feature = "falcon")]
            KeyType::Falcon => write!(f, "Falcon"),
            #[cfg(feature = "ed25519")]
            KeyType::Ed25519 => write!(f, "Ed25519"),
            KeyType::Other(value) => write!(f, "Other({})", value),
        }
    }
}

// Convert Algorithm to KeyType
impl From<Algorithm> for KeyType {
    fn from(algo: Algorithm) -> Self {
        match algo {
            Algorithm::RSA => KeyType::Rsa,
            #[cfg(feature = "dilithium")]
            Algorithm::Dilithium => KeyType::Dilithium,
            #[cfg(feature = "falcon")]
            Algorithm::Falcon => KeyType::Falcon,
            #[cfg(feature = "ed25519")]
            Algorithm::Ed25519 => KeyType::Ed25519,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DIDDocument {
    pub id: String,
    pub public_keys: Vec<PublicKey>,
    pub authentication: Vec<Authentication>,
    pub services: Option<Vec<Service>>,
    pub proof: Option<Proof>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKey {
    pub id: String,
    pub type_: KeyType,
    pub controller: String,
    pub public_key_base64: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Authentication {
    pub type_: String,
    pub public_key_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Service {
    pub id: String,
    pub type_: String,
    pub service_endpoint: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Proof {
    pub type_: String,
    pub created: String,
    pub proof_value: String,
    pub verification_method: String,
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey {{ id: {}, type: {}, controller: {} }}",
            self.id, self.type_, self.controller
        )
    }
}

impl DIDDocument {
    pub fn new_with_keys(
        identity_suffix: &str,
        key_id: String,
        key_manager: &mut KeyManager,
        algorithm: Algorithm,
    ) -> Result<Self, IdentityError> {
        let pki = PKIFactory::create_pki(algorithm.clone())?;
        key_manager.add_key(key_id.clone(), pki)?;

        let id = format!("{}:{}", identity_suffix, Uuid::new_v4());
        Ok(DIDDocument {
            id: id.clone(),
            public_keys: vec![PublicKey {
                id: key_id.clone(),
                type_: KeyType::from(algorithm.clone()), // Use the correct mapping
                controller: id.clone(),
                public_key_base64: general_purpose::STANDARD
                    .encode(key_manager.get_public_key(&key_id)?),
            }],
            authentication: vec![Authentication {
                type_: algorithm.to_string(),
                public_key_id: key_id,
            }],
            services: None,
            proof: None,
        })
    }

    pub fn add_public_key(&mut self, pki: &PKI) -> Result<(), IdentityError> {
        let public_key = pki.public_key_raw_bytes();
        if public_key.is_empty() {
            return Err(IdentityError::Other(
                "Public key generation failed".to_string(),
            ));
        }

        let key_type_str = pki.key_type();
        let key_type = match key_type_str.as_str() {
            #[cfg(feature = "pki_rsa")]
            "RSA" => KeyType::Rsa,
            #[cfg(feature = "dilithium")]
            "Dilithium" => KeyType::Dilithium,
            #[cfg(feature = "falcon")]
            "Falcon" => KeyType::Falcon,
            #[cfg(feature = "ed25519")]
            "Ed25519" => KeyType::Ed25519,
            _ => KeyType::Other(key_type_str),
        };

        let public_key_id = format!("key-{}", Uuid::new_v4());

        self.public_keys.push(PublicKey {
            id: public_key_id.clone(),
            type_: key_type.clone(),
            controller: self.id.clone(),
            public_key_base64: general_purpose::STANDARD.encode(public_key),
        });

        self.authentication.push(Authentication {
            type_: key_type.to_string(),
            public_key_id,
        });

        Ok(())
    }
}
