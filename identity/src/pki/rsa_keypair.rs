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

    #[test]
    fn test_invalid_signature_format() {
        let message = b"Test message for RSA!";
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");

        let invalid_signature = vec![0u8; 1000]; // Completely invalid signature
        
        // Verify the invalid signature
        let result = key_pair.verify(message, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }


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


    #[test]
    fn test_public_key_der_encoding() {
        let key_pair = RSAkeyPair::generate_key_pair().expect("Key pair generation failed");
        let public_key = key_pair.get_public_key_raw_bytes();

        // Assert that the public key is not empty
        assert!(!public_key.is_empty(), "Public key should not be empty");

        // Optionally, test if the public key is DER encoded
        assert!(public_key.starts_with(&[0x30]), "Public key should be DER encoded");
    }
}