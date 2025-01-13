// ======================= Public Key Infrastructure (PKI) =======================
// identity\src\pki\kyber_keypair.rs

use crate::pki_error::PKIError;
use crate::{KeyExchange, PKITraits};
#[cfg(feature = "kyber")]
use fips203::ml_kem_1024::{EncapsKey, DecapsKey, KG, CipherText};
#[cfg(feature = "kyber")]
use fips203::traits::{SerDes, KeyGen, Decaps, Encaps};
#[cfg(feature = "kyber")]
use sha2::{Sha256, Digest};

// ======================= Kyber Key Pair Definition =======================
/// Represents a Kyber key pair.

pub struct KyberKeyPair {
    pub public_key: EncapsKey,
    pub private_key: DecapsKey,
}

// ======================= PKITraits Implementation =======================
impl PKITraits for KyberKeyPair {
    type KeyPair = KyberKeyPair;
    type Error = PKIError;

    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let (public_key, private_key) = KG::try_keygen().map_err(|e| {
            PKIError::KeyPairGenerationError(format!("Key generation failed: {:?}", e))
        })?;
        Ok(KyberKeyPair {
            public_key,
            private_key,
        })
    }

    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        self.public_key.clone().into_bytes().to_vec()
    }

    fn key_type() -> String {
        "Kyber".to_string()
    }

    fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        Err(PKIError::UnsupportedOperation("Kyber does not support signing".to_string()))
    }

    fn verify(&self, _data: &[u8], _signature: &[u8]) -> Result<bool, Self::Error> {
        Err(PKIError::UnsupportedOperation("Kyber does not support Verification".to_string()))
    }
}

// ======================= Key Exchange Implementation =======================
impl KeyExchange for KyberKeyPair {
    type SharedSecretKey = Vec<u8>;
    type PublicKey = EncapsKey;
    type PrivateKey = DecapsKey;
    type Error = PKIError;

    fn encapsulate(
        public_key: &Self::PublicKey,
        context: Option<&[u8]>,
    ) -> Result<(Self::SharedSecretKey, Vec<u8>), Self::Error> {
        if let Some(ctx) = context {
            println!("Context provided: {:?}", ctx);
        }

        let (shared_secret, ciphertext) = public_key
            .try_encaps()
            .map_err(|e| PKIError::KeyExchangeError(format!("Encapsulation failed: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&shared_secret.clone().into_bytes());
        hasher.update(&ciphertext.clone().into_bytes());
        let validation_tag = hasher.finalize();

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

        let tag_length = Sha256::output_size();
        if ciphertext.len() < 1568 + tag_length {
            return Err(PKIError::KeyExchangeError("Invalid ciphertext length".to_string()));
        }

        let (ciphertext_part, validation_tag) = ciphertext.split_at(1568);

        let ciphertext_array: [u8; 1568] = ciphertext_part.try_into().map_err(|_| {
            PKIError::KeyExchangeError("Failed to convert ciphertext to fixed-size array".to_string())
        })?;
        let ciphertext = CipherText::try_from_bytes(ciphertext_array)
            .map_err(|_| PKIError::KeyExchangeError("Invalid ciphertext format".to_string()))?;

        let shared_secret = private_key
            .try_decaps(&ciphertext)
            .map_err(|e| PKIError::KeyExchangeError(format!("Decapsulation failed: {}", e)))?;

        let mut hasher = Sha256::new();
        hasher.update(&shared_secret.clone().into_bytes());
        hasher.update(&ciphertext.into_bytes());
        let expected_tag = hasher.finalize();

        if validation_tag != expected_tag.as_slice() {
            return Err(PKIError::KeyExchangeError("Validation tag mismatch".to_string()));
        }

        Ok(shared_secret.into_bytes().to_vec())
    }

    fn key_exchange_type() -> String {
        "Kyber".to_string()
    }
}
// ======================= Key Serialization Implmentation =======================
impl crate::KeySerialization for KyberKeyPair {
    fn to_bytes(&self) -> Vec<u8> {
        let public_key_bytes = self.public_key.clone().into_bytes().to_vec();
        let private_key_bytes = self.private_key.clone().into_bytes().to_vec();

        [public_key_bytes, private_key_bytes].concat()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PKIError> {
        let key_len = 1568; // Length of the public key in bytes
        if bytes.len() < 2 * key_len {
            return Err(PKIError::InvalidKey("Insufficient data for deserialization".to_string()));
        }

        let (public_key_bytes, private_key_bytes) = bytes.split_at(key_len);

        let public_key = EncapsKey::try_from_bytes(public_key_bytes.try_into().map_err(|_| {
            PKIError::InvalidKey("Invalid public key length".to_string())
        })?)
        .map_err(|_| PKIError::InvalidKey("Invalid Kyber public key".to_string()))?;

        let private_key = DecapsKey::try_from_bytes(private_key_bytes.try_into().map_err(|_| {
            PKIError::InvalidKey("Invalid private key length".to_string())
        })?)
        .map_err(|_| PKIError::InvalidKey("Invalid Kyber private key".to_string()))?;

        Ok(Self {
            public_key,
            private_key,
        })
    }
}

// ========================= Custom Implmentations ===================================
impl KyberKeyPair {
    pub fn get_private_key(&self) -> &DecapsKey {
        &self.private_key
    }
}
use std::fmt;

impl fmt::Debug for KyberKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "KyberKeyPair {{ public_key: {:?}, private_key: {:?} }}",
            &self.public_key.clone().into_bytes(), // Convert the EncapsKey to bytes
            &self.private_key.clone().into_bytes()  // Convert the DecapsKey to bytes
        )
    }
}