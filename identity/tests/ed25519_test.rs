
#[cfg(test)]
#[cfg(feature = "ed25519")]
mod tests {
    use std::time::Instant;
    use identity::{Ed25519KeyPair,PKITraits,KeyExchange};
    use curve25519_dalek::{EdwardsPoint,Scalar};
    #[test]
    fn test_ed25519_keypair() {
        let message = b"Hello, ED25519!";

        // Start timing
        let start = Instant::now();

        // Test key pair generation
        let key_pair = Ed25519KeyPair::generate_key_pair()
            .expect("Key pair generation failed");
        println!("ED25519 Key pair generated successfully!");

        let elapsed_keygen = start.elapsed();
        println!("Time taken for ED25519 key pair generation: {:?}", elapsed_keygen);

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
        println!("Total time for ED25519 operations: {:?}", total_elapsed);
    }


    // Edge case: test signature with incorrect length (should fail)
    #[test]
    fn test_invalid_signature_length() {
        let message = b"Test message";

        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let signature = vec![0u8; 63]; // Invalid signature length

        let result = key_pair.verify(message, &signature);
        assert!(result.is_err(), "Verification should fail with invalid signature length");
    }

    // Edge case: test signature with corrupted data (should fail)
    #[test]
    fn test_corrupted_signature() {
        let message = b"Test message";

        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let signature = key_pair.sign(message).expect("Signing failed");

        // Corrupt the signature (flip a bit)
        let mut corrupted_signature = signature.clone();
        corrupted_signature[0] ^= 1;

        let result = key_pair.verify(message, &corrupted_signature);
        assert!(!result.unwrap_or(false), "Verification should fail with corrupted signature");
    }

    // Edge case: test verifying with mismatched message (should fail)
    #[test]
    fn test_verify_mismatched_message() {
        let message = b"Original message";
        let wrong_message = b"Wrong message";

        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let signature = key_pair.sign(message).expect("Signing failed");

        let result = key_pair.verify(wrong_message, &signature);
        assert!(!result.unwrap_or(false), "Verification should fail with mismatched message");
    }

    // Edge case: test signature verification with an empty message (should pass)
    #[test]
    fn test_empty_message_verification() {
        let message: &[u8] = b""; // Empty message

        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let signature = key_pair.sign(message).expect("Signing failed");

        let result = key_pair.verify(message, &signature);
        assert!(result.unwrap_or(false), "Verification should pass with an empty message");
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_keypair_generation_consistency() {
        let key_pair1 = Ed25519KeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = Ed25519KeyPair::generate_key_pair().expect("Second key pair generation failed");

        assert_ne!(
            key_pair1.get_public_key_raw_bytes(),
            key_pair2.get_public_key_raw_bytes(),
            "Each generated public key should be unique"
        );
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_unique_signatures() {
        let data = b"Test data for signing";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            // Generate a new key pair for each signature
            let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");

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

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_key_type_return() {
        let key_type = Ed25519KeyPair::key_type();
        assert_eq!(key_type, "ED25519", "The key_type() should return 'ED25519'");
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_sign_and_verify() {
        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        // Sign the data
        let signature = key_pair.sign(data).expect("Signing failed");

        // Verify the signature
        let is_valid = key_pair.verify(data, &signature).expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_invalid_signature_format() {
        let key_pair = Ed25519KeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        let invalid_signature = vec![0u8; 32]; // Invalid signature length for ED25519

        let result = key_pair.verify(data, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }

    #[test]
    fn test_ed25519_key_exchange() {
        // Generate key pairs for Alice and Bob
        let alice_key_pair = Ed25519KeyPair::generate_key_pair().unwrap();
        let bob_key_pair = Ed25519KeyPair::generate_key_pair().unwrap();

        // Convert signing keys to X25519 keys (scalars)
        let alice_private_key = Scalar::from_bytes_mod_order(alice_key_pair.signing_key.to_bytes());
        let bob_private_key = Scalar::from_bytes_mod_order(bob_key_pair.signing_key.to_bytes());

        // Convert verifying keys to Montgomery points (public keys for X25519)
        let alice_public_key = EdwardsPoint::mul_base(&alice_private_key).to_montgomery();
        let bob_public_key = EdwardsPoint::mul_base(&bob_private_key).to_montgomery();

        // Perform key exchange
        // Alice encapsulates using Bob's public key
        let (alice_shared_secret, alice_ciphertext) = Ed25519KeyPair::encapsulate(&bob_public_key, None).unwrap();
        // Bob decapsulates using his private key and the ciphertext from Alice
        let bob_shared_secret = Ed25519KeyPair::decapsulate(&bob_private_key, &alice_ciphertext, None).unwrap();

        // Verify that shared secrets match
        assert_eq!(alice_shared_secret, bob_shared_secret);
    }

    #[test]
    fn test_ed25519_key_exchange_type() {
        assert_eq!(Ed25519KeyPair::key_exchange_type(), "X25519-Ed25519");
    }

    #[test]
    fn test_ed25519_get_public_key() {
        let key_pair = Ed25519KeyPair::generate_key_pair().unwrap();
        let public_key = key_pair.get_public_key_raw_bytes();
        assert_eq!(public_key.len(), 32); // Ed25519 public key should be 32 bytes
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        let key_pair = Ed25519KeyPair::generate_key_pair().unwrap();
        let message = b"This is a test message";

        let signature = key_pair.sign(message).unwrap();
        let is_valid = key_pair.verify(message, &signature).unwrap();

        assert!(is_valid);
    }
}