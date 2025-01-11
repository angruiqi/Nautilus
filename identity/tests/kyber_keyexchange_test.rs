#[cfg(test)]
#[cfg(feature = "kyber")]
mod tests {
    use fips203::ml_kem_1024::KG;
    use identity::{KyberKeyPair,KeyExchange};
    use fips203::traits::KeyGen;
    #[test]
    fn test_encapsulation_and_decapsulation() {
        // Generate a key pair
        let (encaps_key, decaps_key) = KG::try_keygen().expect("Key generation failed");

        // Perform encapsulation
        let (shared_secret, ciphertext) = KyberKeyPair::encapsulate(&encaps_key, None)
            .expect("Encapsulation failed");

        // Perform decapsulation
        let recovered_secret =
            KyberKeyPair::decapsulate(&decaps_key, &ciphertext, None)
                .expect("Decapsulation failed");

        // Ensure shared secret matches
        assert_eq!(shared_secret, recovered_secret, "Shared secrets do not match");
    }

    #[test]
    fn test_encapsulation_with_context() {
        // Generate a key pair
        let (encaps_key, _) = KG::try_keygen().expect("Key generation failed");

        // Provide context
        let context = b"SessionID:12345";

        // Perform encapsulation
        let result = KyberKeyPair::encapsulate(&encaps_key, Some(context));
        assert!(result.is_ok(), "Encapsulation with context failed");
    }

    #[test]
    fn test_decapsulation_invalid_ciphertext_length() {
        // Generate a key pair
        let (_, decaps_key) = KG::try_keygen().expect("Key generation failed");

        // Invalid ciphertext (length less than 1568)
        let invalid_ciphertext = vec![0u8; 1000];

        // Perform decapsulation
        let result = KyberKeyPair::decapsulate(&decaps_key, &invalid_ciphertext, None);
        assert!(
            result.is_err(),
            "Decapsulation should fail for invalid ciphertext length"
        );
    }

    #[test]
    fn test_decapsulation_malformed_ciphertext() {
        // Generate a key pair
        let (_, decaps_key) = KG::try_keygen().expect("Key generation failed");

        // Malformed ciphertext with correct length
        let malformed_ciphertext = vec![0xFF; 1568];

        // Perform decapsulation
        let result = KyberKeyPair::decapsulate(&decaps_key, &malformed_ciphertext, None);
        assert!(
            result.is_err(),
            "Decapsulation should fail for malformed ciphertext"
        );
    }
    #[test]
    fn test_encapsulation_and_decapsulation_with_invalid_key() {
        // Generate two separate key pairs
        let (encaps_key_1, _) = KG::try_keygen().expect("Key generation failed");
        let (_, decaps_key_2) = KG::try_keygen().expect("Key generation failed");
    
        // Encapsulate using the first public key
        let (_, ciphertext) = KyberKeyPair::encapsulate(&encaps_key_1, None)
            .expect("Encapsulation failed");
    
        // Attempt to decapsulate with the second private key (mismatched)
        let result = KyberKeyPair::decapsulate(&decaps_key_2, &ciphertext, None);
        assert!(
            result.is_err(),
            "Decapsulation should fail with mismatched keys"
        );
    }
    

    #[test]
    fn test_encapsulation_and_decapsulation_edge_case_context() {
        // Generate a key pair
        let (encaps_key, decaps_key) = KG::try_keygen().expect("Key generation failed");

        // Provide an unusual context
        let context = b"";

        // Perform encapsulation
        let (shared_secret, ciphertext) =
            KyberKeyPair::encapsulate(&encaps_key, Some(context))
                .expect("Encapsulation failed");

        // Perform decapsulation with the same context
        let recovered_secret =
            KyberKeyPair::decapsulate(&decaps_key, &ciphertext, Some(context))
                .expect("Decapsulation failed");

        // Ensure shared secret matches
        assert_eq!(shared_secret, recovered_secret, "Shared secrets do not match");
    }

    #[test]
    fn test_key_exchange_type() {
        // Ensure the key exchange type is correctly identified
        assert_eq!(
            KyberKeyPair::key_exchange_type(),
            "Kyber",
            "Key exchange type does not match"
        );
    }
}