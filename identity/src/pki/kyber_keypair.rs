// identity\src\pki\kyber_keypair.rs
use crate::pki_error::PKIError;
use crate::KeyExchange;
#[cfg(feature = "kyber")]
use fips203::ml_kem_1024::{EncapsKey, DecapsKey, KG};
#[cfg(feature = "kyber")]
use fips203::traits::{Decaps, Encaps, SerDes, KeyGen};
#[cfg(feature = "kyber")]
use crate::PKITraits;
#[cfg(feature = "kyber")]
use sha2::{Sha256, Digest};
#[cfg(feature = "kyber")]
use fips203::ml_kem_1024::CipherText;
use serde::{Serialize, Deserialize};
use serde_bytes::{ByteBuf};


/// Represents a Kyber key pair.
#[derive(Serialize, Deserialize)]
pub struct KyberKeyPair {
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub private_key: Vec<u8>,
}

impl KyberKeyPair {
    // Helper function to convert to fips203 EncapsKey
    fn get_encaps_key(&self) -> Result<EncapsKey, PKIError> {
        EncapsKey::try_from_bytes(self.public_key.clone().try_into().map_err(|_| {
            PKIError::InvalidKey("Failed to convert public key bytes".to_string())
        })?)
        .map_err(|_| PKIError::InvalidKey("Invalid public key format".to_string()))
    }

    // Helper function to convert to fips203 DecapsKey
    fn get_decaps_key(&self) -> Result<DecapsKey, PKIError> {
        DecapsKey::try_from_bytes(self.private_key.clone().try_into().map_err(|_| {
            PKIError::InvalidKey("Failed to convert private key bytes".to_string())
        })?)
        .map_err(|_| PKIError::InvalidKey("Invalid private key format".to_string()))
    }
}

impl PKITraits for KyberKeyPair {
    type KeyPair = KyberKeyPair;
    type Error = PKIError;

    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let (public_key, private_key) = KG::try_keygen().map_err(|e| {
            PKIError::KeyPairGenerationError(format!("Key generation failed: {:?}", e))
        })?;
        Ok(KyberKeyPair {
            public_key: public_key.into_bytes().to_vec(),
            private_key: private_key.into_bytes().to_vec(),
        })
    }

    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    fn key_type() -> String {
        "Kyber".to_string()
    }

    // For now, signing and verification can be placeholders or `unimplemented!()` if not required.
    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(PKIError::UnsupportedOperation("Kyber does not support signing".to_string()))
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, Self::Error> {
        Err(PKIError::UnsupportedOperation("Kyber does not support Verification".to_string()))
    }
}


impl KeyExchange for KyberKeyPair{
    type SharedSecretKey = Vec<u8>;
    type PublicKey = Vec<u8>;
    type PrivateKey = Vec<u8>;
    type Error = PKIError;

   fn encapsulate(
        public_key: &Self::PublicKey,
        context: Option<&[u8]>,
    ) -> Result<(Self::SharedSecretKey, Vec<u8>), Self::Error> {
        if let Some(ctx) = context {
            println!("Context provided: {:?}", ctx);
        }

        let encaps_key = EncapsKey::try_from_bytes(public_key.clone().try_into().map_err(|_| {
            PKIError::InvalidKey("Failed to convert public key bytes".to_string())
        })?)
        .map_err(|_| PKIError::InvalidKey("Invalid public key format".to_string()))?;

        let (shared_secret, ciphertext) = encaps_key
            .try_encaps()
            .map_err(|e| PKIError::KeyExchangeError(format!("Encapsulation failed: {}", e)))?;

        // Create a validation tag by hashing the shared secret and ciphertext
        let mut hasher = Sha256::new();
        hasher.update(&shared_secret.clone().into_bytes()); // Clone shared_secret
        hasher.update(&ciphertext.clone().into_bytes()); // Clone ciphertext
        let validation_tag = hasher.finalize();

        // Append the validation tag to the ciphertext
        let mut ciphertext_vec = ciphertext.into_bytes().to_vec();
        ciphertext_vec.extend_from_slice(&validation_tag);

        Ok((shared_secret.into_bytes().to_vec(), ciphertext_vec))
    }

   fn decapsulate(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        context: Option<&[u8]>,
    ) -> Result<Self::SharedSecretKey, Self::Error> {
        if let Some(ctx) = context {
            println!("Context provided: {:?}", ctx);
        }

        let decaps_key = DecapsKey::try_from_bytes(private_key.clone().try_into().map_err(|_| {
            PKIError::InvalidKey("Failed to convert private key bytes".to_string())
        })?)
        .map_err(|_| PKIError::InvalidKey("Invalid private key format".to_string()))?;

        let tag_length = Sha256::output_size();
        if ciphertext.len() < 1568 + tag_length {
            return Err(PKIError::KeyExchangeError("Invalid ciphertext length".to_string()));
        }

        // Separate the original ciphertext and the validation tag
        let (ciphertext_part, validation_tag) = ciphertext.split_at(1568);

        // Convert the ciphertext part back to CipherText format
        let ciphertext_array: [u8; 1568] = ciphertext_part.try_into().map_err(|_| {
            PKIError::KeyExchangeError("Failed to convert ciphertext to fixed-size array".to_string())
        })?;
        let ciphertext = CipherText::try_from_bytes(ciphertext_array)
            .map_err(|_| PKIError::KeyExchangeError("Invalid ciphertext format".to_string()))?;

        let shared_secret = decaps_key
            .try_decaps(&ciphertext)
            .map_err(|e| PKIError::KeyExchangeError(format!("Decapsulation failed: {}", e)))?;

        // Recompute the validation tag
        let mut hasher = Sha256::new();
        hasher.update(&shared_secret.clone().into_bytes());
        hasher.update(&ciphertext.into_bytes());
        let expected_tag = hasher.finalize();

        // Validate the tag
        if validation_tag != expected_tag.as_slice() {
            return Err(PKIError::KeyExchangeError("Validation tag mismatch".to_string()));
        }

        Ok(shared_secret.into_bytes().to_vec())
    }

    fn key_exchange_type() -> String {
        "Kyber".to_string()
    }
}