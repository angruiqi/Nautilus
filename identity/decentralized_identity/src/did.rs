use serde::{Serialize, Deserialize};
use std::fmt;
use crate::{IdentityError,PKI,KeyManager,Algorithm,PKIFactory};
use uuid::Uuid;
use base64::engine::general_purpose;
use base64::Engine as _; // For encoding

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum KeyType {
    Ecdsa,
    Rsa,
    Other(String),
}

impl fmt::Display for KeyType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyType::Ecdsa => write!(f, "Ecdsa"),
            KeyType::Rsa => write!(f, "Rsa"),
            KeyType::Other(value) => write!(f, "Other({})", value),
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
        let pki = PKIFactory::create_pki(algorithm.clone())?; // Clone the algorithm
    
        key_manager.add_key(key_id.clone(), pki)?;
    
        let id = format!("{}:{}", identity_suffix, Uuid::new_v4());
        Ok(DIDDocument {
            id: id.clone(), // Clone the id
            public_keys: vec![crate::PublicKey {
                id: key_id.clone(),
                type_: crate::KeyType::Other(algorithm.to_string()),
                controller: id.clone(), // Use the cloned id
                public_key_base64: general_purpose::STANDARD.encode(key_manager.get_public_key(&key_id)?),
            }],
            authentication: vec![crate::Authentication {
                type_: algorithm.to_string(),
                public_key_id: key_id,
            }],
            services: None,
            proof: None,
        })
    }

    pub fn add_public_key(
        &mut self,
        pki: &PKI,
    ) -> Result<(), IdentityError> {
        let public_key = pki.public_key_raw_bytes();
        if public_key.is_empty() {
            return Err(IdentityError::Other("Public key generation failed".to_string()));
        }
        let key_type = pki.key_type();
        let public_key_id = format!("key-{}", Uuid::new_v4());

        self.public_keys.push(PublicKey {
            id: public_key_id.clone(),
            type_: KeyType::Other(key_type.clone()),
            controller: self.id.clone(),
            public_key_base64: general_purpose::STANDARD.encode(public_key),
        });
        self.authentication.push(Authentication {
            type_: key_type,
            public_key_id,
        });

        Ok(())
    }
} 

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{KeyManager, Algorithm};

    #[test]
    fn test_did_document_generation_with_algorithms() {
        let mut key_manager = KeyManager::new();
        let identity_suffix = "did:example";

        // Define the algorithms to test
        let algorithms = vec![
            Algorithm::RSA,
            #[cfg(feature = "dilithium")]
            Algorithm::Dilithium,
            #[cfg(feature = "falcon")]
            Algorithm::Falcon,
            #[cfg(feature = "ed25519")]
            Algorithm::Ed25519,
        ];

        for algorithm in algorithms {
            let key_id = format!("key-{}", uuid::Uuid::new_v4());
            println!("Testing DIDDocument creation with algorithm: {:?}", algorithm);

            // Create a DIDDocument
            let did_document = DIDDocument::new_with_keys(
                identity_suffix,
                key_id.clone(),
                &mut key_manager,
                algorithm.clone(),
            );

            // Assert successful creation
            assert!(did_document.is_ok(), "Failed to create DIDDocument with {:?}", algorithm);

            let did_document = did_document.unwrap();
            println!("Generated DIDDocument: {:?}", did_document);

            // Check that the public key is correctly added
            assert_eq!(
                did_document.public_keys.len(),
                1,
                "DIDDocument should have 1 public key for {:?}",
                algorithm
            );

            // Check the public key ID and type
            let public_key = &did_document.public_keys[0];
            assert_eq!(
                public_key.type_.to_string(),
                format!("Other({})", algorithm),
                "Public key type mismatch for {:?}",
                algorithm
            );
            assert_eq!(public_key.id, key_id, "Public key ID mismatch for {:?}", algorithm);
        }
    }
}