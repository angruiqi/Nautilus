
#[cfg(feature = "pki_rsa")]
#[cfg(test)]
mod tests {
  use identity::{RSAkeyPair, PKITraits,KeyExchange};
  use rsa::{
      pkcs1::EncodeRsaPrivateKey,
      pkcs1v15::SigningKey,
      signature::{RandomizedSigner, SignatureEncoding},
      RsaPrivateKey, RsaPublicKey,
  };
  use rsa::pkcs1::EncodeRsaPublicKey;
  use sha2::Sha256;
  use rand_core::OsRng;



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
        use rsa::pkcs1::DecodeRsaPrivateKey;
    
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

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_rsa_encapsulation_and_decapsulation() {
        // Generate RSA key pair
        let rsa_key_pair = RSAkeyPair::generate_key_pair().expect("Failed to generate RSA key pair");

        // Perform encapsulation
        let (session_key, ciphertext) = RSAkeyPair::encapsulate(&rsa_key_pair.public_key, None)
            .expect("Encapsulation failed");

        // Perform decapsulation
        let recovered_session_key =
            RSAkeyPair::decapsulate(&rsa_key_pair.private_key, &ciphertext, None)
                .expect("Decapsulation failed");

        // Verify that the session key matches the recovered session key
        assert_eq!(
            session_key, recovered_session_key,
            "Session keys should match"
        );
    }

    #[test]
fn test_rsa_encapsulation_and_decapsulation_with_valid_tag() {
    // Generate RSA key pair
    let rsa_key_pair = RSAkeyPair::generate_key_pair().expect("Failed to generate RSA key pair");

    // Perform encapsulation
    let (session_key, combined_ciphertext) = RSAkeyPair::encapsulate(&rsa_key_pair.public_key, None)
        .expect("Encapsulation failed");

    // Perform decapsulation
    let recovered_session_key =
        RSAkeyPair::decapsulate(&rsa_key_pair.private_key, &combined_ciphertext, None)
            .expect("Decapsulation failed");

    // Verify that the session key matches the recovered session key
    assert_eq!(
        session_key, recovered_session_key,
        "Session keys should match"
    );
}

#[test]
fn test_rsa_decapsulation_with_invalid_tag() {
    // Generate RSA key pair
    let rsa_key_pair = RSAkeyPair::generate_key_pair().expect("Failed to generate RSA key pair");

    // Perform encapsulation
    let (_, mut combined_ciphertext) = RSAkeyPair::encapsulate(&rsa_key_pair.public_key, None)
        .expect("Encapsulation failed");

    // Tamper with the tag (last byte)
    let len = combined_ciphertext.len();
    combined_ciphertext[len - 1] ^= 0xFF;

    // Attempt decapsulation
    let result = RSAkeyPair::decapsulate(&rsa_key_pair.private_key, &combined_ciphertext, None);

    // Verify that decapsulation fails due to invalid tag
    assert!(
        result.is_err(),
        "Decapsulation should fail with invalid tag"
    );
}

}