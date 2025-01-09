// identity\src\pki\ed25519_keypair.rs
#[cfg(feature = "ed25519")]
use crate::{PKIError, PKITraits}; 
#[cfg(feature = "ed25519")]
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
#[cfg(feature = "ed25519")]
use rand_core::{OsRng, RngCore};
#[cfg(feature = "ed25519")]
use std::convert::TryInto;

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

#[cfg(test)]
#[cfg(feature = "ed25519")]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_ed25519_keypair() {
        let message = b"Hello, ED25519!";

        // Start timing
        let start = Instant::now();

        // Test key pair generation
        let key_pair = Ed25519KeyPair::generate_key_pair()
            .expect("Key pair generation failed");
        println!("ED25519 Key pair generated successfully!");

        let elapsed_keygen = start.elapsed();
        println!("Time taken for ED25519 key pair generation: {:?}", elapsed_keygen);

        // Test signing
        let sign_start = Instant::now();
        let signature = key_pair.sign(message).expect("Signing failed");
        println!("Message signed successfully!");

        let elapsed_sign = sign_start.elapsed();
        println!("Time taken for signing: {:?}", elapsed_sign);

        // Test verification
        let verify_start = Instant::now();
        let is_valid = key_pair.verify(message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature is not valid");
        println!("Signature valid!");

        let elapsed_verify = verify_start.elapsed();
        println!("Time taken for verification: {:?}", elapsed_verify);

        // Total elapsed time
        let total_elapsed = start.elapsed();
        println!("Total time for ED25519 operations: {:?}", total_elapsed);
    }


    // Edge case: test signature with incorrect length (should fail)
    #[test]
    fn test_invalid_signature_length() {
        let message = b"Test message";

        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let signature = vec![0u8; 63]; // Invalid signature length

        let result = key_pair.verify(message, &signature);
        assert!(result.is_err(), "Verification should fail with invalid signature length");
    }

    // Edge case: test signature with corrupted data (should fail)
    #[test]
    fn test_corrupted_signature() {
        let message = b"Test message";

        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let signature = key_pair.sign(message).expect("Signing failed");

        // Corrupt the signature (flip a bit)
        let mut corrupted_signature = signature.clone();
        corrupted_signature[0] ^= 1;

        let result = key_pair.verify(message, &corrupted_signature);
        assert!(!result.unwrap_or(false), "Verification should fail with corrupted signature");
    }

    // Edge case: test verifying with mismatched message (should fail)
    #[test]
    fn test_verify_mismatched_message() {
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let signature = key_pair.sign(message).expect("Signing failed");

        let result = key_pair.verify(wrong_message, &signature);
        assert!(!result.unwrap_or(false), "Verification should fail with mismatched message");
    }

    // Edge case: test signature verification with an empty message (should pass)
    #[test]
    fn test_empty_message_verification() {
        let message: &[u8] = b""; // Empty message

        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let signature = key_pair.sign(message).expect("Signing failed");

        let result = key_pair.verify(message, &signature);
        assert!(result.unwrap_or(false), "Verification should pass with an empty message");
    }

}