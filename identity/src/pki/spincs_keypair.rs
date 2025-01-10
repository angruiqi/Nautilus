// identity\src\pki\spincs_keypair.rs
#[cfg(feature = "spincs")]
use crate::{PKIError, PKITraits}; 
#[cfg(feature = "spincs")]
use fips205::slh_dsa_shake_256s::{self, PrivateKey, PublicKey};
#[cfg(feature = "spincs")]
use fips205::traits::{SerDes, Signer, Verifier};

#[cfg(feature = "spincs")]
pub struct SPHINCSKeyPair {
  pub private_key: PrivateKey,
  pub public_key: PublicKey,
}
#[cfg(feature = "spincs")]
impl PKITraits for SPHINCSKeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    /// Generates a new SPHINCS+ key pair.
    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let (public_key, private_key) = slh_dsa_shake_256s::try_keygen()
            .map_err(|e| PKIError::KeyPairGenerationError(format!("Key generation failed: {}", e)))?;

        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Signs data using the private key.
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signature = self
            .private_key
            .try_sign(data, &[], false)
            .map_err(|e| PKIError::SigningError(format!("Signing failed: {}", e)))?;

        Ok(signature.to_vec())
    }

    /// Verifies a signature using the public key.
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let signature_array: [u8; slh_dsa_shake_256s::SIG_LEN] = signature
            .try_into()
            .map_err(|_| PKIError::VerificationError("Invalid signature length".to_string()))?;

        let is_valid = self.public_key.verify(data, &signature_array, &[]);
        Ok(is_valid)
    }

    /// Retrieves the public key from the key pair.
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        self.public_key.clone().into_bytes().to_vec()
    }

    /// Retrieves the key type.
    fn key_type() -> String {
        "SPHINCS+".to_string()
    }
}

#[cfg(test)]
#[cfg(feature = "spincs")]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_sphincs_keypair() {
        let message = b"Hello, SPHINCS+!";

        // Start timing
        let start = Instant::now();

        // Test key pair generation
        let key_pair = SPHINCSKeyPair::generate_key_pair()
            .expect("Key pair generation failed");
        println!("SPHINCS+ Key pair generated successfully!");

        let elapsed_keygen = start.elapsed();
        println!("Time taken for SPHINCS+ key pair generation: {:?}", elapsed_keygen);

        // Test signing
        let sign_start = Instant::now();
        let signature = key_pair.sign(message)
            .expect("Signing failed");
        println!("Message signed successfully!");

        let elapsed_sign = sign_start.elapsed();
        println!("Time taken for signing: {:?}", elapsed_sign);

        // Test verification
        let verify_start = Instant::now();
        let is_valid = key_pair.verify(message, &signature)
            .expect("Verification failed");
        assert!(is_valid, "Signature is not valid");
        println!("Signature valid!");

        let elapsed_verify = verify_start.elapsed();
        println!("Time taken for verification: {:?}", elapsed_verify);

        // Total elapsed time
        let total_elapsed = start.elapsed();
        println!("Total time for SPHINCS+ operations: {:?}", total_elapsed);
    }
    
    #[cfg(feature = "spincs")]
    #[test]
    fn test_keypair_generation_consistency() {
        let key_pair1 = SPHINCSKeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = SPHINCSKeyPair::generate_key_pair().expect("Second key pair generation failed");

        assert_ne!(
            key_pair1.get_public_key_raw_bytes(),
            key_pair2.get_public_key_raw_bytes(),
            "Each generated public key should be unique"
        );
    }

    #[cfg(feature = "spincs")]
    #[test]
    fn test_unique_signatures() {
        let data = b"Test data for signing";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            let key_pair = SPHINCSKeyPair::generate_key_pair().expect("Key pair generation failed");
            let signature = key_pair.sign(data).expect("Signing failed");
            signatures.push(signature);
        }

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

    #[cfg(feature = "spincs")]
    #[test]
    fn test_key_type_return() {
        let key_type = SPHINCSKeyPair::key_type();
        assert_eq!(key_type, "SPHINCS+", "The key_type() should return 'SPHINCS+'");
    }

    #[cfg(feature = "spincs")]
    #[test]
    fn test_sign_and_verify() {
        let key_pair = SPHINCSKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        let signature = key_pair.sign(data).expect("Signing failed");
        let is_valid = key_pair.verify(data, &signature).expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");
    }

    #[cfg(feature = "spincs")]
    #[test]
    fn test_invalid_signature_format() {
        let key_pair = SPHINCSKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        let invalid_signature = vec![0u8; slh_dsa_shake_256s::SIG_LEN - 1]; // Invalid signature length

        let result = key_pair.verify(data, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }

    #[cfg(feature = "spincs")]
    #[test]
    fn test_keypair_generation_edge_cases() {
        // Simulate failure in key generation
        let result = std::panic::catch_unwind(|| SPHINCSKeyPair::generate_key_pair());
        assert!(result.is_ok(), "Key pair generation should not panic");
    }

    #[cfg(feature = "spincs")]
    #[test]
    fn test_large_message_sign_and_verify() {
        let key_pair = SPHINCSKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = vec![0u8; 10_000]; // Large message

        let signature = key_pair.sign(&data).expect("Signing failed");
        let is_valid = key_pair.verify(&data, &signature).expect("Verification failed");

        assert!(is_valid, "Signature verification for large message should succeed");
    }

}