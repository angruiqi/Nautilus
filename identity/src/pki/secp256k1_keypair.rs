// ======================= Public Key Infrastructure (PKI) =======================
// identity\src\pki\secp256k1_keypair.rs

#[cfg(feature = "secp256k1")]
use crate::{PKIError, PKITraits, KeyExchange};
#[cfg(feature = "secp256k1")]
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
#[cfg(feature = "secp256k1")]
use rand_core::OsRng;
#[cfg(feature = "secp256k1")]
use k256::elliptic_curve::sec1::ToEncodedPoint;

// ======================= SECP256K1 Key Pair Definition =======================
#[cfg(feature = "secp256k1")]
pub struct SECP256K1KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

// ======================= PKITraits Implementation =======================
#[cfg(feature = "secp256k1")]
impl PKITraits for SECP256K1KeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    /// Generates a new SECP256K1 key pair.
    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = *signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Signs data using the private key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signature: Signature = self.signing_key.sign(data);
        Ok(signature.to_der().to_bytes().to_vec())
    }

    /// Verifies a signature using the public key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let signature = Signature::from_der(signature)
            .map_err(|e| PKIError::VerificationError(format!("Invalid signature format: {}", e)))?;
        self.verifying_key
            .verify(data, &signature)
            .map(|_| true)
            .map_err(|e| PKIError::VerificationError(format!("Verification failed: {}", e)))
    }

    /// Retrieves the public key from the key pair.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        // Get the public key in uncompressed format (0x04 indicates uncompressed)
        self.verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Retrieves the key type.
    fn key_type() -> String {
        "SECP256K1".to_string()
    }
}

// ======================= Key Exchange Implementation =======================
#[cfg(feature = "secp256k1")]
impl KeyExchange for SECP256K1KeyPair {
    type SharedSecretKey = Vec<u8>;
    type PublicKey = k256::PublicKey;
    type PrivateKey = k256::SecretKey;
    type Error = PKIError;

    /// Encapsulate a shared secret
    fn encapsulate(
        public_key: &Self::PublicKey,
        _context: Option<&[u8]>,
    ) -> Result<(Self::SharedSecretKey, Vec<u8>), Self::Error> {
        let ephemeral_private_key = k256::SecretKey::random(&mut OsRng);
        let ephemeral_public_key = ephemeral_private_key.public_key();

        // Compute the shared secret
        let shared_secret = k256::ecdh::diffie_hellman(
            ephemeral_private_key.to_nonzero_scalar(),
            public_key.as_affine(),
        );

        Ok((
            shared_secret.raw_secret_bytes().to_vec(),
            ephemeral_public_key.to_encoded_point(false).as_bytes().to_vec(),
        ))
    }

    /// Decapsulate a shared secret
    fn decapsulate(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<Self::SharedSecretKey, Self::Error> {
        // Reconstruct the peer's public key from the ciphertext
        let peer_public_key = k256::PublicKey::from_sec1_bytes(ciphertext)
            .map_err(|e| {
                PKIError::KeyExchangeError(format!("Invalid public key format: {}", e))
            })?;

        // Compute the shared secret
        let shared_secret = k256::ecdh::diffie_hellman(
            private_key.to_nonzero_scalar(),
            peer_public_key.as_affine(),
        );

        Ok(shared_secret.raw_secret_bytes().to_vec())
    }

    /// Retrieve the key exchange type
    fn key_exchange_type() -> String {
        "SECP256K1-ECDH".to_string()
    }
}
// ======================= Key Serialization Implmentation =======================
#[cfg(feature = "secp256k1")]
impl crate::KeySerialization for SECP256K1KeyPair {
    fn to_bytes(&self) -> Vec<u8> {
        let signing_key_bytes = self.signing_key.to_bytes().to_vec();
        let verifying_key_bytes = self.verifying_key.to_encoded_point(false).as_bytes().to_vec();

        [signing_key_bytes, verifying_key_bytes].concat()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PKIError> {
        let signing_key_size = 32; // SECP256K1 private key size
        if bytes.len() <= signing_key_size {
            return Err(PKIError::InvalidKey("Insufficient data for deserialization".to_string()));
        }

        let (signing_key_bytes, verifying_key_bytes) = bytes.split_at(signing_key_size);

        let signing_key = SigningKey::from_bytes(signing_key_bytes.into())
            .map_err(|_| PKIError::InvalidKey("Invalid SECP256K1 private key".to_string()))?;
        let verifying_key = VerifyingKey::from_sec1_bytes(verifying_key_bytes)
            .map_err(|_| PKIError::InvalidKey("Invalid SECP256K1 public key".to_string()))?;

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
}
