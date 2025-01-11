// identity\src\pki\ed25519_keypair.rs
#[cfg(feature = "ed25519")]
use crate::{PKIError, PKITraits,KeyExchange}; 
#[cfg(feature = "ed25519")]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(feature = "ed25519")]
use rand_core::{OsRng, RngCore};
#[cfg(feature = "ed25519")]
use std::convert::TryInto;
#[cfg(feature = "ed25519")]
use curve25519_dalek::scalar::Scalar;
#[cfg(feature = "ed25519")]
use curve25519_dalek::MontgomeryPoint;
#[cfg(feature = "ed25519")]
use curve25519_dalek::edwards::EdwardsPoint;
#[cfg(feature = "ed25519")]
pub struct Ed25519KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

#[cfg(feature = "ed25519")]
impl PKITraits for Ed25519KeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    /// Generates a new Ed25519 key pair.
    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let mut private_key = [0u8; 32];
        OsRng.fill_bytes(&mut private_key);

        let signing_key = SigningKey::from_bytes(&private_key);
        let verifying_key = signing_key.verifying_key();

        Ok(Self {
            signing_key,
            verifying_key,
        })
    }

    /// Signs data using the private key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signature = self.signing_key.sign(data);
        Ok(signature.to_bytes().to_vec())
    }

    /// Verifies a signature using the public key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        // Ensure the signature is the correct length (64 bytes for ED25519)
        let signature_array: [u8; 64] = signature
            .try_into()
            .map_err(|_| PKIError::VerificationError("Invalid signature length".to_string()))?;

        // Convert the signature array into a Signature object
        let signature = Signature::from_bytes(&signature_array);

        // Perform the verification and map errors to PKIError
        self.verifying_key
            .verify(data, &signature)
            .map(|_| true)
            .map_err(|e| PKIError::VerificationError(format!("Verification failed: {}", e)))
    }

    /// Retrieves the public key from the key pair.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        // Assuming the public key is a fixed-size array, convert it to Vec<u8>
        self.verifying_key.clone().to_bytes().to_vec() // Convert array to Vec<u8>
    }
    /// Retrieves the key type.
    fn key_type() -> String {
        "ED25519".to_string()
    }
}



#[cfg(feature = "ed25519")]
impl KeyExchange for Ed25519KeyPair {
    type SharedSecretKey = Vec<u8>;
    type PublicKey = MontgomeryPoint;
    type PrivateKey = Scalar;
    type Error = PKIError;

    fn encapsulate(
        public_key: &Self::PublicKey,
        _context: Option<&[u8]>,
    ) -> Result<(Self::SharedSecretKey, Vec<u8>), Self::Error> {
        let mut rng = OsRng;

        // Generate an ephemeral X25519 private key
        let ephemeral_private_key = {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            Scalar::from_bytes_mod_order(bytes)
        };

        let ephemeral_public_key = EdwardsPoint::mul_base(&ephemeral_private_key).to_montgomery();

        // Compute the shared secret
        let shared_secret = public_key * ephemeral_private_key;

        // Return the shared secret and the ephemeral public key
        Ok((shared_secret.to_bytes().to_vec(), ephemeral_public_key.to_bytes().to_vec()))
    }

    fn decapsulate(
        private_key: &Self::PrivateKey,
        ciphertext: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<Self::SharedSecretKey, Self::Error> {
        // Ensure the ciphertext is the correct length (32 bytes for a MontgomeryPoint)
        if ciphertext.len() != 32 {
            return Err(PKIError::KeyExchangeError(
                "Invalid ciphertext length".to_string(),
            ));
        }
    
        // Convert the ciphertext to a MontgomeryPoint
        let peer_public_key = MontgomeryPoint(ciphertext.try_into().unwrap());
    
        // Compute the shared secret
        let shared_secret = peer_public_key * private_key;
    
        // Return the shared secret
        Ok(shared_secret.to_bytes().to_vec())
    }

    fn key_exchange_type() -> String {
        "X25519-Ed25519".to_string()
    }
}