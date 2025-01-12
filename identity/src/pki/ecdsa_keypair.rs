// ======================= Public Key Infrastructure (PKI) =======================
// identity\src\pki\ecdsa_keypair.rs

#[cfg(feature = "ecdsa")]
use crate::{PKIError, PKITraits, KeyExchange};
#[cfg(feature = "ecdsa")]
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
#[cfg(feature = "ecdsa")]
use p256::{
    elliptic_curve::point::AffineCoordinates,
    elliptic_curve::PrimeField,
    AffinePoint, ProjectivePoint, PublicKey, Scalar,
};
#[cfg(feature = "ecdsa")]
use sha2::Digest;
#[cfg(feature = "ecdsa")]
use rand_core::OsRng;

// ======================= ECDSA Key Pair Definition =======================
#[cfg(feature = "ecdsa")]
pub struct ECDSAKeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

// ======================= PKITraits Implementation =======================
#[cfg(feature = "ecdsa")]
impl PKITraits for ECDSAKeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    /// Generates a new ECDSA key pair.
    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = VerifyingKey::from(&signing_key);

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Signs data using the private key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signature: Signature = self.signing_key.sign(data);
        Ok(signature.to_der().as_bytes().to_vec())
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
        self.verifying_key.to_encoded_point(false).as_bytes().to_vec()
    }

    /// Retrieves the key type.
    fn key_type() -> String {
        "ECDSA".to_string()
    }
}

// ======================= Key Exchange Implementation =======================
#[cfg(feature = "ecdsa")]
impl KeyExchange for ECDSAKeyPair {
    type SharedSecretKey = Vec<u8>;
    type PublicKey = PublicKey;
    type PrivateKey = SigningKey;
    type Error = PKIError;

    /// Perform ECDH encapsulation (derive shared secret and generate ephemeral public key).
    fn encapsulate(
        public_key: &Self::PublicKey,
        _context: Option<&[u8]>,
    ) -> Result<(Self::SharedSecretKey, Vec<u8>), Self::Error> {
        let ephemeral_secret = SigningKey::random(&mut OsRng);
        let ephemeral_public_key = VerifyingKey::from(&ephemeral_secret).to_encoded_point(false);

        let peer_point = ProjectivePoint::from(public_key);
        let secret_scalar = Scalar::from_repr_vartime(ephemeral_secret.to_bytes().into())
            .ok_or_else(|| PKIError::KeyExchangeError("Invalid scalar bytes".to_string()))?;
        let shared_point = peer_point * secret_scalar;
        let shared_point_affine = AffinePoint::from(shared_point);
        let shared_secret = shared_point_affine.x().to_vec();

        let mut hasher = sha2::Sha256::new();
        hasher.update(&shared_secret);
        hasher.update(ephemeral_public_key.as_bytes());
        let validation_tag = hasher.finalize();

        let mut ciphertext = ephemeral_public_key.as_bytes().to_vec();
        ciphertext.extend_from_slice(&validation_tag);

        Ok((shared_secret, ciphertext))
    }

    /// Perform ECDH decapsulation (derive shared secret using private key and peer's public key).
    fn decapsulate(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<Self::SharedSecretKey, Self::Error> {
        let tag_length = sha2::Sha256::output_size();
        if ciphertext.len() < tag_length {
            return Err(PKIError::KeyExchangeError("Invalid ciphertext length".to_string()));
        }
        let (encoded_public_key, validation_tag) = ciphertext.split_at(ciphertext.len() - tag_length);

        let peer_public_key = PublicKey::from_sec1_bytes(encoded_public_key).map_err(|e| {
            PKIError::KeyExchangeError(format!("Invalid peer public key: {}", e))
        })?;

        let peer_point = ProjectivePoint::from(&peer_public_key);

        let secret_scalar = Scalar::from_repr_vartime(private_key.to_bytes().into())
            .ok_or_else(|| PKIError::KeyExchangeError("Invalid scalar bytes".to_string()))?;

        let shared_point = peer_point * secret_scalar;
        let shared_point_affine = AffinePoint::from(shared_point);
        let shared_secret = shared_point_affine.x().to_vec();

        let mut hasher = sha2::Sha256::new();
        hasher.update(&shared_secret);
        hasher.update(encoded_public_key);
        let expected_tag = hasher.finalize();

        if validation_tag != expected_tag.as_slice() {
            return Err(PKIError::KeyExchangeError("Validation tag mismatch".to_string()));
        }

        Ok(shared_secret)
    }

    /// Retrieve the type of key exchange mechanism.
    fn key_exchange_type() -> String {
        "ECDH-ECDSA".to_string()
    }
}

// ======================= Key Serialization Implementation =======================
#[cfg(feature = "ecdsa")]
impl crate::KeySerialization for ECDSAKeyPair {
    fn to_bytes(&self) -> Vec<u8> {
        let signing_key_bytes = self.signing_key.to_bytes().to_vec();
        let verifying_key_bytes = self.verifying_key.to_encoded_point(false).as_bytes().to_vec();

        [signing_key_bytes, verifying_key_bytes].concat()
    }

    fn from_bytes(bytes: &[u8]) -> Result<Self, PKIError> {
        let signing_key_size = 32; // ECDSA private key size
        if bytes.len() < signing_key_size + 65 {
            return Err(PKIError::InvalidKey("Insufficient data for deserialization".to_string()));
        }

        let (signing_key_bytes, verifying_key_bytes) = bytes.split_at(signing_key_size);

        let signing_key = SigningKey::from_bytes(signing_key_bytes.into()).map_err(|_| {
            PKIError::InvalidKey("Invalid ECDSA private key size".to_string())
        })?;

        let verifying_key = VerifyingKey::from_sec1_bytes(verifying_key_bytes).map_err(|_| {
            PKIError::InvalidKey("Invalid ECDSA public key size".to_string())
        })?;

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }
}

// ======================= Key Serialization Implementation ==============================
#[cfg(feature = "ecdsa")]
impl ECDSAKeyPair {
    /// Compute the shared secret using ECDH.
        /// Compute the shared secret using ECDH.
        #[deprecated]
        pub fn compute_shared_secret(
            &self,
            peer_public_key: &[u8], // Raw public key bytes from the peer
        ) -> Result<Vec<u8>, PKIError> {
            // Parse the peer's public key
            let peer_pub_key = PublicKey::from_sec1_bytes(peer_public_key)
                .map_err(|e| PKIError::KeyExchangeError(format!("Invalid peer public key: {}", e)))?;
    
            // Convert the peer's public key to a ProjectivePoint
            let peer_point = ProjectivePoint::from(&peer_pub_key);
    
            // Extract the secret scalar from the signing key
            let secret_scalar = Scalar::from_repr_vartime(self.signing_key.to_bytes().into())
                .ok_or_else(|| PKIError::KeyExchangeError("Invalid scalar bytes".to_string()))?;
    
            // Perform scalar multiplication
            let shared_point = peer_point * secret_scalar;
    
            // Convert the shared point to affine coordinates and extract the x-coordinate as the shared secret
            let shared_point_affine = AffinePoint::from(shared_point);
            let shared_secret = shared_point_affine.x().to_vec();
    
            Ok(shared_secret)
        }
}