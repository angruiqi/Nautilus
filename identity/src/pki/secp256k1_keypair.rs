// identity\src\pki\secp256k1_keypair.rs
#[cfg(feature = "secp256k1")]
use crate::{PKIError, PKITraits};
#[cfg(feature = "secp256k1")]
use k256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
#[cfg(feature = "secp256k1")]
use rand_core::OsRng;
#[cfg(feature = "secp256k1")]
pub struct SECP256K1KeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

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
        self.verifying_key.to_encoded_point(false).as_bytes().to_vec() // Convert array to Vec<u8>
    }
    /// Retrieves the key type.
    fn key_type() -> String {
        "SECP256K1".to_string()
    }
}

#[cfg(test)]
#[cfg(feature = "secp256k1")]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_secp256k1_keypair() {
        let message = b"Hello, SECP256K1!";

        // Start timing
        let start = Instant::now();

        // Test key pair generation
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");
        println!("SECP256K1 Key pair generated successfully!");

        let elapsed_keygen = start.elapsed();
        println!(
            "Time taken for SECP256K1 key pair generation: {:?}",
            elapsed_keygen
        );

        // Test signing
        let sign_start = Instant::now();
        let signature = key_pair.sign(message).expect("Signing failed");
        println!("Message signed successfully!");

        let elapsed_sign = sign_start.elapsed();
        println!("Time taken for signing: {:?}", elapsed_sign);

        // Test verification
        let verify_start = Instant::now();
        let is_valid = key_pair
            .verify(message, &signature)
            .expect("Verification failed");
        assert!(is_valid, "Signature is not valid");
        println!("Signature valid!");

        let elapsed_verify = verify_start.elapsed();
        println!("Time taken for verification: {:?}", elapsed_verify);

        // Total elapsed time
        let total_elapsed = start.elapsed();
        println!("Total time for SECP256K1 operations: {:?}", total_elapsed);
    }

    #[test]
    fn test_verify_invalid_signature() {
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");
        let message = b"Hello, SECP256K1!";
        let invalid_signature = vec![0u8; 64]; // Completely invalid signature

        // Verify the invalid signature
        let is_valid = key_pair
            .verify(message, &invalid_signature)
            .unwrap_or(false);
        assert!(!is_valid, "Invalid signature should not be valid");
    }

    #[test]
    fn test_invalid_signature_format() {
        let message = b"Test message for SECP256K1!";
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");

        let invalid_signature = vec![0u8; 64]; // Invalid signature (incorrect format)

        // Verify the invalid signature
        let result = key_pair.verify(message, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }
    #[test]
    fn test_empty_message() {
        let message = b""; // Empty message
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with empty message
        let signature = key_pair.sign(message).expect("Signing failed");

        // Test verification with empty message
        let is_valid = key_pair.verify(message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for empty message");
    }


    #[test]
    fn test_corrupted_signature() {
        let message = b"Test message for SECP256K1";
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");

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
        let message = b"Test message for SECP256K1";
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");

        // Generate a different key pair for incorrect verification
        let incorrect_key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Verify with incorrect public key
        let is_valid = incorrect_key_pair.verify(message, &signature).unwrap_or(false);
        assert!(!is_valid, "Signature should not be valid with incorrect public key");
    }


    #[test]
    fn test_small_message() {
        let small_message = b"A"; // Single-byte message
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with small message
        let signature = key_pair.sign(small_message).expect("Signing failed");

        // Test verification with small message
        let is_valid = key_pair.verify(small_message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for small message");
    }
    #[test]
    fn test_invalid_signature_length() {
        let message = b"Test message for SECP256K1";
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Create an invalid signature by modifying its length
        let invalid_signature = signature[..signature.len() - 1].to_vec(); // Truncate by 1 byte

        // Verify the invalid signature
        let is_valid = key_pair.verify(message, &invalid_signature).unwrap_or(false);
        assert!(!is_valid, "Signature should be invalid due to incorrect length");
    }


    #[cfg(feature = "secp256k1")]
    #[test]
    fn test_keypair_generation_consistency() {
        let key_pair1 = SECP256K1KeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = SECP256K1KeyPair::generate_key_pair().expect("Second key pair generation failed");

        assert_ne!(
            key_pair1.get_public_key_raw_bytes(),
            key_pair2.get_public_key_raw_bytes(),
            "Each generated public key should be unique"
        );
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn test_unique_signatures() {
        let data = b"Test data for signing";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            // Generate a new key pair for each signature
            let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");

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

    #[cfg(feature = "secp256k1")]
    #[test]
    fn test_key_type_return() {
        let key_type = SECP256K1KeyPair::key_type();
        assert_eq!(key_type, "SECP256K1", "The key_type() should return 'SECP256K1'");
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn test_sign_and_verify() {
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        // Sign the data
        let signature = key_pair.sign(data).expect("Signing failed");

        // Verify the signature
        let is_valid = key_pair.verify(data, &signature).expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");
    }

  
}
