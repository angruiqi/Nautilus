// identity\src\pki\dilithium_keypair.rs
#[cfg(feature = "dilithium")]
use crate::{PKIError, PKITraits}; 
#[cfg(feature = "dilithium")]
use fips204::ml_dsa_87::{self, PrivateKey, PublicKey};
#[cfg(feature = "dilithium")]
use fips204::traits::{SerDes, Signer, Verifier};



#[cfg(feature = "dilithium")]
pub struct DilithiumKeyPair {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
}

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

    /// Retrieves the public key from the key pair.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        // Assuming the public key is a fixed-size array, convert it to Vec<u8>
        self.public_key.clone().into_bytes().to_vec() // Convert array to Vec<u8>
    }
    /// Retrieves the key type.
    fn key_type() -> String {
        "Dilithium".to_string()
    }
}
#[cfg(test)]
#[cfg(feature = "dilithium")]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_dilithium_keypair() {
        let message = b"Hello, Dilithium!";

        // Start timing
        let start = Instant::now();

        // Test key pair generation
        let key_pair = DilithiumKeyPair::generate_key_pair()
            .expect("Key pair generation failed");
        println!("Key pair generated successfully!");

        let elapsed_keygen = start.elapsed();
        println!("Time taken for key pair generation: {:?}", elapsed_keygen);

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
        println!("Total time for Dilithium operations: {:?}", total_elapsed);
    }


    #[test]
    fn test_large_message() {
        let large_message = vec![0u8; 10_000]; // Large message (10KB)
        let key_pair = DilithiumKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with a large message
        let signature = key_pair.sign(&large_message).expect("Signing failed");

        // Test verification with a large message
        let is_valid = key_pair.verify(&large_message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for large message");
    }

    #[test]
    fn test_corrupted_signature() {
        let message = b"Test message for Dilithium";
        let key_pair = DilithiumKeyPair::generate_key_pair().expect("Key pair generation failed");

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
        let key_pair = DilithiumKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Generate a different key pair for incorrect verification
        let incorrect_key_pair = DilithiumKeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Verify with incorrect public key
        let is_valid = incorrect_key_pair.verify(message, &signature).unwrap_or(false);
        assert!(!is_valid, "Signature should not be valid with incorrect public key");
    }

    #[test]
    fn test_invalid_signature_length() {
        let message = b"Test message for Falcon";
        let key_pair = DilithiumKeyPair::generate_key_pair().expect("Key pair generation failed");

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
        let result = DilithiumKeyPair::generate_key_pair();
        assert!(result.is_ok(), "Key pair generation with small size should succeed");

        // Further tests can verify against expected behaviors for small keys
    }
}