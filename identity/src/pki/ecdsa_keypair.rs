// identity\src\pki\ecdsa_keypair.rs
#[cfg(feature = "ecdsa")]
use crate::{PKIError, PKITraits}; 
#[cfg(feature = "ecdsa")]
use p256::ecdsa::{
    signature::{Signer, Verifier},
    Signature, SigningKey, VerifyingKey,
};
#[cfg(feature = "ecdsa")]
use p256::{
    elliptic_curve::point::AffineCoordinates,elliptic_curve::PrimeField,
    AffinePoint, ProjectivePoint, PublicKey, Scalar,
};

#[cfg(feature = "ecdsa")]
use rand_core::OsRng;

#[cfg(feature = "ecdsa")]
pub struct ECDSAKeyPair {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

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
        // Get the public key in uncompressed format (0x04 indicates uncompressed)
        self.verifying_key.to_encoded_point(false).as_bytes().to_vec() // Convert array to Vec<u8>
    }
    
    /// Retrieves the key type.
    fn key_type() -> String {
        "ECDSA".to_string()
    }
}
#[cfg(feature = "ecdsa")]
impl ECDSAKeyPair {
    /// Compute the shared secret using ECDH.
        /// Compute the shared secret using ECDH.
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
#[cfg(test)]
#[cfg(feature = "ecdsa")]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_ecdsa_keypair() {
        let message = b"Hello, ECDSA!";

        // Start timing
        let start = Instant::now();

        // Test key pair generation
        let key_pair = ECDSAKeyPair::generate_key_pair()
            .expect("Key pair generation failed");
        println!("ECDSA Key pair generated successfully!");

        let elapsed_keygen = start.elapsed();
        println!("Time taken for ECDSA key pair generation: {:?}", elapsed_keygen);

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
        println!("Total time for ECDSA operations: {:?}", total_elapsed);
    }


    #[test]
    fn test_invalid_signature_format() {
        let message = b"Test message for ECDSA!";
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

        let invalid_signature = vec![0u8; 64]; // Invalid signature (incorrect format)

        // Verify the invalid signature
        let result = key_pair.verify(message, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }


    #[test]
    fn test_empty_message() {
        let message = b""; // Empty message
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with empty message
        let signature = key_pair.sign(message).expect("Signing failed");

        // Test verification with empty message
        let is_valid = key_pair.verify(message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for empty message");
    }


    #[test]
    fn test_large_message() {
        let large_message = vec![0u8; 10_000]; // Large message (10KB)
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with large message
        let signature = key_pair.sign(&large_message).expect("Signing failed");

        // Test verification with large message
        let is_valid = key_pair.verify(&large_message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for large message");
    }


    #[test]
    fn test_corrupted_signature() {
        let message = b"Test message for ECDSA";
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

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
        let message = b"Test message for ECDSA";
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Generate a different key pair for incorrect verification
        let incorrect_key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Verify with incorrect public key
        let is_valid = incorrect_key_pair.verify(message, &signature).unwrap_or(false);
        assert!(!is_valid, "Signature should not be valid with incorrect public key");
    }



    #[test]
    fn test_small_message() {
        let small_message = b"A"; // Single-byte message
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with small message
        let signature = key_pair.sign(small_message).expect("Signing failed");

        // Test verification with small message
        let is_valid = key_pair.verify(small_message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for small message");
    }


    #[test]
    fn test_invalid_signature_length() {
        let message = b"Test message for ECDSA";
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Create an invalid signature by modifying its length
        let invalid_signature = signature[..signature.len() - 1].to_vec(); // Truncate by 1 byte

        // Verify the invalid signature
        let is_valid = key_pair.verify(message, &invalid_signature).unwrap_or(false);
        assert!(!is_valid, "Signature should be invalid due to incorrect length");
    }

    #[test]
    fn test_shared_secret() {
        let client_key_pair = ECDSAKeyPair::generate_key_pair().unwrap();
        let server_key_pair = ECDSAKeyPair::generate_key_pair().unwrap();
    
        let client_public_key = client_key_pair.get_public_key_raw_bytes();
        let server_public_key = server_key_pair.get_public_key_raw_bytes();
    
        let client_secret = client_key_pair.compute_shared_secret(&server_public_key).unwrap();
        let server_secret = server_key_pair.compute_shared_secret(&client_public_key).unwrap();
    
        assert_eq!(client_secret, server_secret);
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn test_keypair_generation_consistency() {
        let key_pair1 = ECDSAKeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = ECDSAKeyPair::generate_key_pair().expect("Second key pair generation failed");

        assert_ne!(
            key_pair1.get_public_key_raw_bytes(),
            key_pair2.get_public_key_raw_bytes(),
            "Each generated public key should be unique"
        );
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn test_unique_signatures() {
        let data = b"Test data for signing";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            // Generate a new key pair for each signature
            let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

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

    #[cfg(feature = "ecdsa")]
    #[test]
    fn test_key_type_return() {
        let key_type = ECDSAKeyPair::key_type();
        assert_eq!(key_type, "ECDSA", "The key_type() should return 'ECDSA'");
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn test_sign_and_verify() {
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        // Sign the data
        let signature = key_pair.sign(data).expect("Signing failed");

        // Verify the signature
        let is_valid = key_pair.verify(data, &signature).expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");
    }

    #[cfg(feature = "ecdsa")]
    #[test]
    fn test_compute_shared_secret() {
        let key_pair1 = ECDSAKeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = ECDSAKeyPair::generate_key_pair().expect("Second key pair generation failed");

        let public_key2 = key_pair2.get_public_key_raw_bytes();

        // Compute the shared secret from both perspectives
        let shared_secret1 = key_pair1
            .compute_shared_secret(&public_key2)
            .expect("Shared secret computation failed for key_pair1");

        let shared_secret2 = key_pair2
            .compute_shared_secret(&key_pair1.get_public_key_raw_bytes())
            .expect("Shared secret computation failed for key_pair2");

        // Ensure the shared secrets match
        assert_eq!(
            shared_secret1, shared_secret2,
            "Shared secrets computed by both parties should match"
        );
    }
    
}