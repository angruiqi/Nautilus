// ======================= Public Key Infrastructure (PKI) =======================
// identity\src\pki\dilithium_keypair.rs

#[cfg(feature = "dilithium")]
use crate::{PKIError, PKITraits};
#[cfg(feature = "dilithium")]
use fips204::ml_dsa_87::{self, PrivateKey, PublicKey};
#[cfg(feature = "dilithium")]
use fips204::traits::{SerDes, Signer, Verifier};

// ======================= Dilithium Key Pair Definition =======================
/// A struct representing a Dilithium key pair.
///
/// This struct encapsulates the private and public keys required for
/// signing and verification using the Dilithium digital signature algorithm.
#[cfg(feature = "dilithium")]
pub struct DilithiumKeyPair {
    /// The private key used for signing.
    pub private_key: PrivateKey,
    /// The public key used for verification.
    pub public_key: PublicKey,
}

// ======================= PKITraits Implementation =======================
#[cfg(feature = "dilithium")]
impl PKITraits for DilithiumKeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    /// Generates a new Dilithium key pair.
    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let result = std::panic::catch_unwind(|| {
            ml_dsa_87::try_keygen()
                .map_err(|e| PKIError::KeyPairGenerationError(format!("Key generation failed: {}", e)))
        });

        match result {
            Ok(Ok((public_key, private_key))) => Ok(Self {
                private_key,
                public_key,
            }),
            Ok(Err(e)) => Err(e),
            Err(_) => {
                eprintln!(
                    "A stack overflow occurred during key pair generation.\n\n\
                     To resolve this issue, please increase your stack size:\n\n\
                     **For Windows:**\n\
                     $env:RUSTFLAGS=\"-C link-arg=/STACK:8388608\"\n\
                     cargo run\n\n\
                     **For Linux/Mac:**\n\
                     RUSTFLAGS=\"-C link-arg=-zstack-size=8388608\" cargo run\n\n\
                     Alternatively, run the operation in a thread with an increased stack size."
                );
                Err(PKIError::KeyPairGenerationError(
                    "Stack overflow during key pair generation".to_string(),
                ))
            }
        }
    }

    /// Signs data using the private key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signature = self
            .private_key
            .try_sign(data, &[])
            .map_err(|e| PKIError::SigningError(format!("Signing failed: {}", e)))?;
        Ok(signature.to_vec())
    }

    /// Verifies a signature using the public key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let signature_array: [u8; 4627] = signature
            .try_into()
            .map_err(|_| PKIError::VerificationError("Invalid signature length".to_string()))?;

        let is_valid = self.public_key.verify(data, &signature_array, &[]);
        Ok(is_valid)
    }

    /// Retrieves the public key as raw bytes.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        self.public_key.clone().into_bytes().to_vec()
    }

    /// Retrieves the key type as a string.
    fn key_type() -> String {
        "Dilithium".to_string()
    }
}

// ======================= Key Serialization Implementation =======================
#[cfg(feature = "dilithium")]
impl crate::KeySerialization for DilithiumKeyPair {
    fn to_bytes(&self) -> Vec<u8> {
        let public_key_bytes = self.public_key.clone().into_bytes().to_vec();
        let private_key_bytes = self.private_key.clone().into_bytes().to_vec();

        [public_key_bytes, private_key_bytes].concat()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PKIError> {
        let public_key_len = 2592; // Confirmed from PublicKey::into_bytes()
        let private_key_len = 4896; // Confirmed from PrivateKey::into_bytes()
    
        if bytes.len() != public_key_len + private_key_len {
            return Err(PKIError::InvalidKey(format!(
                "Invalid key length for Dilithium. Expected {}, got {}",
                public_key_len + private_key_len,
                bytes.len()
            )));
        }
    
        let (public_key_bytes, private_key_bytes) = bytes.split_at(public_key_len);
    
        let public_key = PublicKey::try_from_bytes(public_key_bytes.try_into().map_err(|_| {
            PKIError::InvalidKey("Invalid public key length".to_string())
        })?)
        .map_err(|_| PKIError::InvalidKey("Invalid Dilithium public key".to_string()))?;
    
        let private_key = PrivateKey::try_from_bytes(private_key_bytes.try_into().map_err(|_| {
            PKIError::InvalidKey("Invalid private key length".to_string())
        })?)
        .map_err(|_| PKIError::InvalidKey("Invalid Dilithium private key".to_string()))?;
    
        Ok(Self {
            public_key,
            private_key,
        })
    }
}