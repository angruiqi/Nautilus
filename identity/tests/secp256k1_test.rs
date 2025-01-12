
#[cfg(test)]
#[cfg(feature = "secp256k1")]
mod tests {
    use std::time::Instant;
    use identity::{SECP256K1KeyPair,PKITraits,KeyExchange};
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

    #[test]
    fn test_secp256k1_key_exchange() {
        // Generate key pairs for Alice and Bob
        let alice_key_pair = SECP256K1KeyPair::generate_key_pair().unwrap();
        let bob_key_pair = SECP256K1KeyPair::generate_key_pair().unwrap();

        // Convert signing keys to secret keys
        let alice_secret_key = k256::SecretKey::from(alice_key_pair.signing_key);
        let bob_secret_key = k256::SecretKey::from(bob_key_pair.signing_key);

        // Convert verifying keys to public keys
        let alice_public_key = alice_secret_key.public_key();
        let bob_public_key = bob_secret_key.public_key();

        // Perform key exchange
        let (alice_shared_secret, alice_ciphertext) =
            SECP256K1KeyPair::encapsulate(&bob_public_key, None).unwrap();
        let bob_shared_secret =
            SECP256K1KeyPair::decapsulate(&bob_secret_key, &alice_ciphertext, None).unwrap();

        // Verify that shared secrets match
        assert_eq!(alice_shared_secret, bob_shared_secret);
    }

    #[test]
    fn test_secp256k1_key_exchange_type() {
        assert_eq!(SECP256K1KeyPair::key_exchange_type(), "SECP256K1-ECDH");
    }

    #[test]
    fn test_secp256k1_get_public_key() {
        let key_pair = SECP256K1KeyPair::generate_key_pair().unwrap();
        let public_key_bytes = key_pair.get_public_key_raw_bytes();

        // SECP256k1 uncompressed public key: 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes
        assert_eq!(public_key_bytes.len(), 65);
        assert_eq!(public_key_bytes[0], 0x04); // Check for uncompressed format
    }

    #[test]
    fn test_secp256k1_sign_and_verify() {
        let key_pair = SECP256K1KeyPair::generate_key_pair().unwrap();
        let message = b"This is a test message";

        let signature = key_pair.sign(message).unwrap();
        let is_valid = key_pair.verify(message, &signature).unwrap();

        assert!(is_valid);
    }

    #[test]
    fn test_secp256k1_verify_invalid_signature() {
        let key_pair = SECP256K1KeyPair::generate_key_pair().unwrap();
        let message = b"This is a test message";

        // Create an invalid signature (e.g., all zeros with incorrect length)
        let invalid_signature = vec![0u8; 72]; // Use a more realistic invalid signature length

        let result = key_pair.verify(message, &invalid_signature);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid signature format")); // Expect a format error now
    }

    #[test]
    fn test_secp256k1_decapsulate_invalid_ciphertext() {
        let key_pair = SECP256K1KeyPair::generate_key_pair().unwrap();
        let secret_key = k256::SecretKey::from(key_pair.signing_key);

        // Invalid ciphertext length
        let invalid_ciphertext = vec![0u8; 31];
        let result = SECP256K1KeyPair::decapsulate(&secret_key, &invalid_ciphertext, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid public key format"));

        // Invalid ciphertext format (not a valid point)
        let invalid_ciphertext = vec![0u8; 65];
        let result = SECP256K1KeyPair::decapsulate(&secret_key, &invalid_ciphertext, None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Invalid public key format"));
    }
}


#[cfg(feature = "secp256k1")]
#[cfg(test)]
mod serialization_test {
    use identity::{SECP256K1KeyPair,PKITraits,KeySerialization};

    #[test]
    fn test_serialization_and_deserialization() {
        let key_pair = SECP256K1KeyPair::generate_key_pair().expect("Failed to generate key pair");
        let serialized = key_pair.to_bytes();

        let deserialized = SECP256K1KeyPair::from_bytes(&serialized).expect("Failed to deserialize key pair");

        assert_eq!(key_pair.signing_key.to_bytes().to_vec(), deserialized.signing_key.to_bytes().to_vec());
        assert_eq!(key_pair.verifying_key.to_encoded_point(false).as_bytes().to_vec(), deserialized.verifying_key.to_encoded_point(false).as_bytes().to_vec());
    }

    #[test]
    fn test_invalid_deserialization() {
        let invalid_bytes = vec![0u8; 16];
        let result = SECP256K1KeyPair::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }
}
