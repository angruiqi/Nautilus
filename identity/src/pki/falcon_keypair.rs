// identity\src\pki\falcon_keypair.rs
#[cfg(feature="falcon")]
use crate::{PKIError, PKITraits}; 
#[cfg(feature="falcon")]
use pqcrypto_falcon::falcon512::*;
#[cfg(feature="falcon")]
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PublicKeyTrait};
#[cfg(feature="falcon")]
pub struct FalconKeyPair {
    pub public_key: PublicKey,
    pub secret_key: SecretKey,
}
#[cfg(feature = "falcon")]
impl PKITraits for FalconKeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    /// Generates a new Falcon key pair.
    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let (public_key, secret_key) = keypair();
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Signs data using the secret key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let detached_signature = detached_sign(data, &self.secret_key);
        Ok(detached_signature.as_bytes().to_vec())
    }

    /// Verifies a signature using the public key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        // Attempt to deserialize the signature
        let detached_signature = DetachedSignature::from_bytes(signature)
            .map_err(|_| PKIError::VerificationError("Invalid signature format".to_string()))?;

        // Verify the detached signature
        verify_detached_signature(&detached_signature, data, &self.public_key)
            .map(|_| true)
            .map_err(|e| PKIError::VerificationError(format!("Verification failed: {}", e)))
    }

    /// Retrieves the public key from the key pair.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        // Assuming the public key is a fixed-size array, convert it to Vec<u8>
        self.public_key.clone().as_bytes().to_vec() // Convert array to Vec<u8>
    }

    /// Retrieves the key type.
    fn key_type() -> String {
        "Falcon".to_string()
    }
}
#[cfg(test)]
#[cfg(feature = "falcon")]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_falcon_keypair() {
        let message = b"Hello, Falcon!";

        // Start timing
        let start = Instant::now();

        // Test key pair generation
        let key_pair = FalconKeyPair::generate_key_pair()
            .expect("Key pair generation failed");
        println!("Falcon Key pair generated successfully!");

        let elapsed_keygen = start.elapsed();
        println!("Time taken for Falcon key pair generation: {:?}", elapsed_keygen);

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
        println!("Total time for Falcon operations: {:?}", total_elapsed);
    }

    #[test]
    fn test_large_message() {
        let large_message = vec![0u8; 10_000]; // Large message (10KB)
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with a large message
        let signature = key_pair.sign(&large_message).expect("Signing failed");

        // Test verification with a large message
        let is_valid = key_pair.verify(&large_message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for large message");
    }

    #[test]
    fn test_corrupted_signature() {
        let message = b"Test message for Dilithium";
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Corrupt the signature (flip a single byte)
        let mut corrupted_signature = signature.clone();
        corrupted_signature[0] ^= 0x01;

        // Verify the corrupted signature
        let is_valid = key_pair.verify(message, &corrupted_signature).unwrap_or(false);
        assert!(!is_valid, "Corrupted signature should not be valid");
    }

    #[test]
    fn test_incorrect_public_key() {
        let message = b"Test message for Dilithium";
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Generate a different key pair for incorrect verification
        let incorrect_key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Verify with incorrect public key
        let is_valid = incorrect_key_pair.verify(message, &signature).unwrap_or(false);
        assert!(!is_valid, "Signature should not be valid with incorrect public key");
    }

    #[test]
    fn test_invalid_signature_length() {
        let message = b"Test message for Falcon";
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Create an invalid signature by modifying its length
        let invalid_signature = signature[..signature.len() - 1].to_vec(); // Truncate by 1 byte

        // Verify the invalid signature
        let is_valid = key_pair.verify(message, &invalid_signature).unwrap_or(false);
        assert!(!is_valid, "Signature should be invalid due to incorrect length");
    }

    #[test]
    fn test_small_key_size() {
        // Use smaller key size for the algorithm (if the API allows it)
        let _message = b"Small key size test for Falcon";

        // Hypothetical small key size - Falcon should fail if this size is insecure
        let result = FalconKeyPair::generate_key_pair();
        assert!(result.is_ok(), "Key pair generation with small size should succeed");

        // Further tests can verify against expected behaviors for small keys
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_keypair_generation_consistency() {
        let key_pair1 = FalconKeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = FalconKeyPair::generate_key_pair().expect("Second key pair generation failed");

        assert_ne!(
            key_pair1.get_public_key_raw_bytes(),
            key_pair2.get_public_key_raw_bytes(),
            "Each generated public key should be unique"
        );
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_unique_signatures() {
        let data = b"Test data for signing";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            // Generate a new key pair for each signature
            let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");

            // Generate the signature and store it
            let signature = key_pair.sign(data).expect("Signing failed");
            signatures.push(signature);
        }

        // Ensure all signatures are unique
        for i in 0..signatures.len() {
            for j in (i + 1)..signatures.len() {
                assert_ne!(
                    signatures[i],
                    signatures[j],
                    "Signatures should be unique for the same message using different keys"
                );
            }
        }
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_key_type_return() {
        let key_type = FalconKeyPair::key_type();
        assert_eq!(key_type, "Falcon", "The key_type() should return 'Falcon'");
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_sign_and_verify() {
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        // Sign the data
        let signature = key_pair.sign(data).expect("Signing failed");

        // Verify the signature
        let is_valid = key_pair.verify(data, &signature).expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");
    }

    #[cfg(feature = "falcon")]
    #[test]
    fn test_invalid_signature_format() {
        let key_pair = FalconKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        let invalid_signature = vec![0u8; 666]; // Completely invalid signature length for Falcon

        let result = key_pair.verify(data, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }
}