// identity\src\pki\dilithium_keypair.rs
#[cfg(feature = "dilithium")]
use crate::{PKIError, PKITraits};
#[cfg(feature = "dilithium")]
use fips204::ml_dsa_87::{self, PrivateKey, PublicKey};
#[cfg(feature = "dilithium")]
use fips204::traits::{SerDes, Signer, Verifier};

// ==================================================== Structs =====================================================

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

// ==================================================== Implementations ==============================================
/// Implementation of the `PKITraits` trait for `DilithiumKeyPair`.
///
/// This provides standard cryptographic operations such as key generation,
/// signing, verification, and retrieval of public key bytes.
#[cfg(feature = "dilithium")]
impl PKITraits for DilithiumKeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    /// Generates a new Dilithium key pair.
    ///
    /// This method uses `ml_dsa_87::try_keygen()` to generate a private-public
    /// key pair. If a stack overflow occurs, it provides guidance on increasing
    /// stack size or running in a thread with more memory.
    ///
    /// # Errors
    /// Returns `PKIError::KeyPairGenerationError` if the key generation fails.
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
    ///
    /// This method takes raw data and signs it using the private key.
    /// The resulting signature is returned as a `Vec<u8>`.
    ///
    /// # Arguments
    /// - `data`: The data to be signed.
    ///
    /// # Errors
    /// Returns `PKIError::SigningError` if the signing operation fails.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signature = self
            .private_key
            .try_sign(data, &[])
            .map_err(|e| PKIError::SigningError(format!("Signing failed: {}", e)))?;
        Ok(signature.to_vec())
    }

    /// Verifies a signature using the public key.
    ///
    /// This method checks the validity of a given signature for the provided
    /// data using the public key.
    ///
    /// # Arguments
    /// - `data`: The original data to verify against.
    /// - `signature`: The signature to be validated.
    ///
    /// # Errors
    /// Returns `PKIError::VerificationError` if the signature length is invalid
    /// or verification fails.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let signature_array: [u8; 4627] = signature
            .try_into()
            .map_err(|_| PKIError::VerificationError("Invalid signature length".to_string()))?;

        let is_valid = self.public_key.verify(data, &signature_array, &[]);
        Ok(is_valid)
    }

    /// Retrieves the public key as raw bytes.
    ///
    /// This method converts the public key into a `Vec<u8>` format suitable for
    /// storage or transmission.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        self.public_key.clone().into_bytes().to_vec()
    }

    /// Retrieves the key type as a string.
    ///
    /// Returns the type of key pair, e.g., "Dilithium".
    fn key_type() -> String {
        "Dilithium".to_string()
    }
}
