#[cfg(test)]
#[cfg(feature = "ecdsa")]
mod tests {
    use std::time::Instant;
    use identity::{ECDSAKeyPair,PKITraits,KeyExchange};

    #[cfg(feature = "ecdsa")]
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

    #[cfg(feature = "ecdsa")]
    #[test]
    fn test_invalid_signature_format() {
        let message = b"Test message for ECDSA!";
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

        let invalid_signature = vec![0u8; 64]; // Invalid signature (incorrect format)

        // Verify the invalid signature
        let result = key_pair.verify(message, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }

    #[cfg(feature = "ecdsa")]
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

    #[cfg(feature = "ecdsa")]
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

    #[cfg(feature = "ecdsa")]
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
    #[cfg(feature = "ecdsa")]
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


    #[cfg(feature = "ecdsa")]
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

    #[cfg(feature = "ecdsa")]
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
    fn test_key_exchange_encapsulation_and_decapsulation() {
        // Generate two key pairs (one for each party)
        let _key_pair_a = ECDSAKeyPair::generate_key_pair().expect("Key pair A generation failed");
        let key_pair_b = ECDSAKeyPair::generate_key_pair().expect("Key pair B generation failed");
    
        // Convert VerifyingKey to PublicKey
        let peer_public_key_b = p256::PublicKey::from_sec1_bytes(
            key_pair_b.verifying_key.to_encoded_point(false).as_bytes(),
        )
        .expect("Failed to convert VerifyingKey to PublicKey");
    
        // Encapsulation by Party A
        let (shared_secret_a, ciphertext) = ECDSAKeyPair::encapsulate(&peer_public_key_b, None)
            .expect("Encapsulation by Party A failed");
    
        // Decapsulation by Party B
        let shared_secret_b = ECDSAKeyPair::decapsulate(&key_pair_b.signing_key, &ciphertext, None)
            .expect("Decapsulation by Party B failed");
    
        // Verify shared secrets match
        assert_eq!(
            shared_secret_a, shared_secret_b,
            "Shared secrets should match between the two parties"
        );
    }

    #[test]
    fn test_key_exchange_with_invalid_ciphertext() {
        // Generate a key pair
        let key_pair = ECDSAKeyPair::generate_key_pair().expect("Key pair generation failed");

        // Use an invalid ciphertext
        let invalid_ciphertext = vec![0u8; 10]; // Incorrect length

        // Attempt decapsulation with invalid ciphertext
        let result = ECDSAKeyPair::decapsulate(&key_pair.signing_key, &invalid_ciphertext, None);
        assert!(
            result.is_err(),
            "Decapsulation should fail for invalid ciphertext"
        );
    }

    #[test]
    fn test_key_exchange_with_mismatched_keys() {
        // Generate two key pairs
        let key_pair_a = ECDSAKeyPair::generate_key_pair().expect("Key pair A generation failed");
        let key_pair_b = ECDSAKeyPair::generate_key_pair().expect("Key pair B generation failed");
    
        // Convert VerifyingKey to PublicKey for Party B
        let peer_public_key_b = p256::PublicKey::from_sec1_bytes(
            key_pair_b.verifying_key.to_encoded_point(false).as_bytes(),
        )
        .expect("Failed to convert VerifyingKey to PublicKey");
    
        // Encapsulation by Party A using Party B's public key
        let (_, ciphertext) = ECDSAKeyPair::encapsulate(&peer_public_key_b, None)
            .expect("Encapsulation failed");
    
        // Attempt decapsulation by Party A with its own private key
        let result = ECDSAKeyPair::decapsulate(&key_pair_a.signing_key, &ciphertext, None);
    
        // Decapsulation should fail because the keys are mismatched
        assert!(
            result.is_err(),
            "Decapsulation should fail for mismatched key pairs"
        );
    }

    #[test]
    fn test_key_exchange_type() {
        let key_type = ECDSAKeyPair::key_exchange_type();
        assert_eq!(
            key_type, "ECDH-ECDSA",
            "Key exchange type should return 'ECDH-ECDSA'"
        );
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