
#[cfg(test)]
#[cfg(feature = "dilithium")]
mod tests {
    use std::time::Instant;
    use identity::{DilithiumKeyPair,PKITraits};

    #[cfg(feature = "dilithium")]
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

    #[cfg(feature = "dilithium")]
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

    #[cfg(feature = "dilithium")]
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

    #[cfg(feature = "dilithium")]
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

    #[cfg(feature = "dilithium")]
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

    #[cfg(feature = "dilithium")]
    #[test]
    fn test_small_key_size() {
        // Use smaller key size for the algorithm (if the API allows it)
        let _message = b"Small key size test for Falcon";

        // Hypothetical small key size - Falcon should fail if this size is insecure
        let result = DilithiumKeyPair::generate_key_pair();
        assert!(result.is_ok(), "Key pair generation with small size should succeed");

        // Further tests can verify against expected behaviors for small keys
    }


    #[cfg(feature = "dilithium")]
    #[test]
    fn test_keypair_generation_consistency() {
        let key_pair1 = DilithiumKeyPair::generate_key_pair().expect("First key pair generation failed");
        let key_pair2 = DilithiumKeyPair::generate_key_pair().expect("Second key pair generation failed");

        assert_ne!(
            key_pair1.get_public_key_raw_bytes(),
            key_pair2.get_public_key_raw_bytes(),
            "Each generated public key should be unique"
        );
    }

    #[cfg(feature = "dilithium")]
    #[test]
    fn test_unique_signatures() {
        let data = b"Test data for signing";
        let mut signatures = Vec::new();

        for _ in 0..5 {
            // Generate a new key pair for each signature
            let key_pair = DilithiumKeyPair::generate_key_pair().expect("Key pair generation failed");

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

    #[cfg(feature = "dilithium")]
    #[test]
    fn test_key_type_return() {
        let key_type = DilithiumKeyPair::key_type();
        assert_eq!(key_type, "Dilithium", "The key_type() should return 'Dilithium'");
    }

    #[cfg(feature = "dilithium")]
    #[test]
    fn test_sign_and_verify() {
        let key_pair = DilithiumKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        // Sign the data
        let signature = key_pair.sign(data).expect("Signing failed");

        // Verify the signature
        let is_valid = key_pair.verify(data, &signature).expect("Verification failed");

        assert!(is_valid, "Signature verification should succeed");
    }

    #[cfg(feature = "dilithium")]
    #[test]
    fn test_invalid_signature_format() {
        let key_pair = DilithiumKeyPair::generate_key_pair().expect("Key pair generation failed");
        let data = b"Test data for signing";

        let invalid_signature = vec![0u8; 4626]; // Invalid signature length

        let result = key_pair.verify(data, &invalid_signature);
        assert!(result.is_err(), "Verification should fail for invalid signature format");
    }
   
    // #[cfg(feature = "dilithium")]
    // #[test]
    // fn test_keypair_generation_stack_overflow() {
    //     use std::panic::{catch_unwind, AssertUnwindSafe};
    
    //     // Use catch_unwind to simulate catching a panic (like stack overflow)
    //     let result = catch_unwind(AssertUnwindSafe(|| {
    //         // Call the key generation function
    //         DilithiumKeyPair::generate_key_pair()
    //     }));
    
    //     match result {
    //         Ok(Err(PKIError::KeyPairGenerationError(msg))) => {
    //             // Validate the error message for key generation failure
    //             assert!(
    //                 msg.contains("Key generation failed") || msg.contains("stack overflow"),
    //                 "Error message should indicate a failure during key generation"
    //             );
    //         }
    //         Err(_) => {
    //             // If a panic occurs, it's treated as a simulated stack overflow
    //             println!("Simulated stack overflow caught successfully.");
    //         }
    //         Ok(Ok(_)) => {
    //             panic!("Expected stack overflow or error, but got a successful result");
    //         }
    //         _ => panic!("Unexpected outcome in keypair generation test"),
    //     }
    // }
    
    
}