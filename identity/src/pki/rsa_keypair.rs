// identity\src\pki\rsa_keypair.rs
#[cfg(feature = "pki_rsa")]
extern crate rsa as rsa_crate;
#[cfg(feature = "pki_rsa")]
use crate::{PKIError, PKITraits};
#[cfg(feature = "pki_rsa")]
use rsa_crate::{
    pkcs1v15::{SigningKey, VerifyingKey, Signature},
    signature::{RandomizedSigner, Verifier, SignatureEncoding},
    RsaPrivateKey, RsaPublicKey, pkcs1::EncodeRsaPublicKey,
};
#[cfg(feature = "pki_rsa")]
use sha2::Sha256;
#[cfg(feature = "pki_rsa")]
use rand_core::OsRng;


#[cfg(feature = "pki_rsa")]
#[derive(Clone)]
pub struct RSAkeyPair {
    pub private_key: RsaPrivateKey,
    pub public_key: RsaPublicKey,
}


#[cfg(feature = "pki_rsa")]
impl PKITraits for RSAkeyPair {
    type KeyPair = Self;
    type Error = PKIError;

    fn generate_key_pair() -> Result<Self::KeyPair, Self::Error> {
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048)
            .map_err(|e| PKIError::KeyPairGenerationError(format!("Key generation failed: {}", e)))?;
        let public_key = RsaPublicKey::from(&private_key);

        Ok(Self {
            private_key,
            public_key,
        })
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        let signing_key = SigningKey::<Sha256>::new(self.private_key.clone());
        let mut rng = OsRng;

        let signature = signing_key.sign_with_rng(&mut rng, data);

        Ok(signature.to_vec())
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Self::Error> {
        let verifying_key = VerifyingKey::<Sha256>::new(self.public_key.clone());

        let signature = Signature::try_from(signature)
            .map_err(|e| PKIError::VerificationError(format!("Invalid signature format: {}", e)))?;

        verifying_key
            .verify(data, &signature)
            .map(|_| true)
            .map_err(|e| PKIError::VerificationError(format!("Verification failed: {}", e)))
    }
    
    fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        // Assuming the public key is a fixed-size array, convert it to Vec<u8>
        self.public_key.to_pkcs1_der().expect("Failed to encode public key to PKCS#8 DER format").as_bytes().to_vec()
    }
    fn key_type() -> String {
        "RSA".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pki::rsa_keypair::rsa_crate::pkcs1::EncodeRsaPrivateKey;

    #[cfg(feature = "pki_rsa")]
    use crate::PKITraits;

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_generate_key_pair() {
        let key_pair = RSAkeyPair::generate_key_pair();
        assert!(key_pair.is_ok(), "Key pair generation should succeed");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_sign_and_verify() {
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        // Sign the data
        let signature = key_pair
            .sign(data)
            .expect("Signing failed");

        // Verify the signature
        let is_valid = key_pair
            .verify(data, &signature)
            .expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_invalid_signature_format() {
        let message = b"Test message for RSA!";
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        let invalid_signature = vec![0u8; 1000]; // Completely invalid signature
        
        // Verify the invalid signature
        let result = key_pair.verify(message, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_empty_message() {
        let message = b""; // Empty message
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with empty message
        let signature = key_pair.sign(message).expect("Signing failed");

        // Test verification with empty message
        let is_valid = key_pair.verify(message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for empty message");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_large_message() {
        let large_message = vec![0u8; 10_000]; // Large message (10KB)
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        // Test signing with a large message
        let signature = key_pair.sign(&large_message).expect("Signing failed");

        // Test verification with a large message
        let is_valid = key_pair.verify(&large_message, &signature).expect("Verification failed");
        assert!(is_valid, "Signature should be valid for large message");
    }

    #[test]
    fn test_corrupted_signature() {
        let message = b"Test message for RSA";
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Corrupt the signature (flip a single byte)
        let mut corrupted_signature = signature.clone();
        corrupted_signature[0] ^= 0x01;

        // Verify the corrupted signature
        let is_valid = key_pair.verify(message, &corrupted_signature).unwrap_or(false);
        assert!(!is_valid, "Corrupted signature should not be valid");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_incorrect_public_key() {
        let message = b"Test message for RSA";
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        // Generate a different key pair for incorrect verification
        let incorrect_key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Verify with incorrect public key
        let is_valid = incorrect_key_pair.verify(message, &signature).unwrap_or(false);
        assert!(!is_valid, "Signature should not be valid with incorrect public key");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_invalid_signature_length() {
        let message = b"Test message for RSA";
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        let signature = key_pair.sign(message).expect("Signing failed");

        // Create an invalid signature by modifying its length
        let invalid_signature = signature[..signature.len() - 1].to_vec(); // Truncate by 1 byte

        // Verify the invalid signature
        let is_valid = key_pair.verify(message, &invalid_signature).unwrap_or(false);
        assert!(!is_valid, "Signature should be invalid due to incorrect length");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_public_key_der_encoding() {
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");
        let public_key = key_pair.get_public_key_raw_bytes();

        // Assert that the public key is not empty
        assert!(!public_key.is_empty(), "Public key should not be empty");

        // Optionally, test if the public key is DER encoded
        assert!(public_key.starts_with(&[0x30]), "Public key should be DER encoded");
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_crash_keypair() {
        use rsa_crate::pkcs1::DecodeRsaPrivateKey;
    
        let mut rng = OsRng;
    
        // Generate a valid RSA private key
        let private_key = RsaPrivateKey::new(&mut rng, 1024).expect("Key generation failed");
    
        // Serialize the private key to DER format
        let mut private_key_der = private_key.to_pkcs1_der().unwrap().as_bytes().to_vec();
    
        // Corrupt the serialized key data (e.g., modify a byte)
        private_key_der[10] ^= 0xFF;
    
        // Attempt to deserialize the corrupted key
        let corrupted_key_result = RsaPrivateKey::from_pkcs1_der(&private_key_der);
    
        // Ensure deserialization of the corrupted key fails
        assert!(
            corrupted_key_result.is_err(),
            "Corrupted private key deserialization should fail"
        );
    
        // If necessary, test the behavior with the corrupted key (should not reach here)
        if let Ok(corrupted_key) = corrupted_key_result {
            let key_pair = RSAkeyPair {
                private_key: corrupted_key,
                public_key: RsaPublicKey::from(&private_key),
            };
    
            let data = b"Test message";
            let result = key_pair.sign(data);
    
            assert!(result.is_err(), "Corrupted private key should not successfully sign data");
        }
    }
    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_keypair_equivalence() {
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");
        let public_key1 = key_pair.public_key.to_pkcs1_der().unwrap();

        // Regenerate the public key from the same private key
        let regenerated_public_key = RsaPublicKey::from(&key_pair.private_key)
            .to_pkcs1_der()
            .unwrap();

        assert_eq!(
            public_key1, regenerated_public_key,
            "Public key should be consistently derived from the same private key"
        );
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_keypair_generation_consistency() {
        let key_pair1 = RSAkeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = RSAkeyPair::generate_key_pair().expect("Second key pair generation failed");

        assert_ne!(
            key_pair1.private_key.to_pkcs1_der().unwrap().as_bytes(),
            key_pair2.private_key.to_pkcs1_der().unwrap().as_bytes(),
            "Each generated private key should be unique"
        );

        assert_ne!(
            key_pair1.public_key.to_pkcs1_der().unwrap(),
            key_pair2.public_key.to_pkcs1_der().unwrap(),
            "Each generated public key should be unique"
        );
    }
    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_different_keypair_variant() {
        let key_pair_2048 = RSAkeyPair::generate_key_pair().expect("Key pair (2048-bit) generation failed");
        let private_key_der_2048 = key_pair_2048.private_key.to_pkcs1_der().unwrap();
        
        // Generate a 4096-bit key pair (assuming RSA supports this in implementation)
        let mut rng = OsRng;
        let private_key_4096 = RsaPrivateKey::new(&mut rng, 4096).expect("4096-bit key generation failed");
        let public_key_4096 = RsaPublicKey::from(&private_key_4096);
        
        assert_ne!(
            private_key_der_2048.len(),
            private_key_4096.to_pkcs1_der().unwrap().len(),
            "Key sizes should differ between 2048-bit and 4096-bit variants"
        );

        assert_ne!(
            key_pair_2048.public_key.to_pkcs1_der().unwrap(),
            public_key_4096.to_pkcs1_der().unwrap(),
            "Public keys of different variants should be different"
        );
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_unique_signatures() {
        let data = b"Test data for signing";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            // Generate a new key pair for each signature
            let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");
            let signing_key = SigningKey::<Sha256>::new(key_pair.private_key);
            let mut rng = OsRng;

            // Generate the signature and store it
            let signature = signing_key
                .sign_with_rng(&mut rng, data)
                .to_vec();
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

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_key_type_return() {
        let key_type = RSAkeyPair::key_type();
        assert_eq!(key_type, "RSA", "The key_type() should return 'RSA'");
    }

}