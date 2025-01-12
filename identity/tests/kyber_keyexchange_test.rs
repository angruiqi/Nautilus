#[cfg(test)]
#[cfg(feature = "kyber")]
mod tests {
    use identity::{KeyExchange,KyberKeyPair,PKITraits};
    #[test]
    fn test_encapsulation_and_decapsulation() {
        // Generate a key pair
        let keypair = KyberKeyPair::generate_key_pair().expect("Key generation failed");

        // Perform encapsulation
        let (shared_secret, ciphertext) = KyberKeyPair::encapsulate(&keypair.public_key, None)
            .expect("Encapsulation failed");

        // Perform decapsulation
        let recovered_secret =
            KyberKeyPair::decapsulate(&keypair.private_key, &ciphertext, None)
                .expect("Decapsulation failed");

        // Ensure shared secret matches
        assert_eq!(shared_secret, recovered_secret, "Shared secrets do not match");
    }

    #[test]
    fn test_encapsulation_with_context() {
        // Generate a key pair
        let keypair = KyberKeyPair::generate_key_pair().expect("Key generation failed");

        // Provide context
        let context = b"SessionID:12345";

        // Perform encapsulation
        let result = KyberKeyPair::encapsulate(&keypair.public_key, Some(context));
        assert!(result.is_ok(), "Encapsulation with context failed");
    }

    #[test]
    fn test_decapsulation_invalid_ciphertext_length() {
        // Generate a key pair
        let keypair = KyberKeyPair::generate_key_pair().expect("Key generation failed");

        // Invalid ciphertext (length less than 1568 + tag length)
        let invalid_ciphertext = vec![0u8; 1000];

        // Perform decapsulation
        let result = KyberKeyPair::decapsulate(&keypair.private_key, &invalid_ciphertext, None);
        assert!(
            result.is_err(),
            "Decapsulation should fail for invalid ciphertext length"
        );
    }
    #[test]
    fn test_decapsulation_malformed_ciphertext() {
        // Generate a key pair
        let keypair = KyberKeyPair::generate_key_pair().expect("Key generation failed");

        // Malformed ciphertext with correct length but invalid content. Here we just fill with zeros.
        // Adjust the length to be valid (1568 for ciphertext + 32 for tag).
        let malformed_ciphertext = vec![0u8; 1568 + 32]; 
    
        // Perform decapsulation
        let result = KyberKeyPair::decapsulate(&keypair.private_key, &malformed_ciphertext, None);
        assert!(result.is_err(), "Decapsulation should fail for malformed ciphertext");
    }
    

    #[test]
    fn test_encapsulation_and_decapsulation_with_invalid_key() {
        // Generate two separate key pairs
        let keypair1 = KyberKeyPair::generate_key_pair().expect("Key generation failed");
        let keypair2 = KyberKeyPair::generate_key_pair().expect("Key generation failed");

        // Encapsulate using the first public key
        let (_, ciphertext) = KyberKeyPair::encapsulate(&keypair1.public_key, None)
            .expect("Encapsulation failed");

        // Attempt to decapsulate with the second private key (mismatched)
        let result = KyberKeyPair::decapsulate(&keypair2.private_key, &ciphertext, None);
        assert!(
            result.is_err(),
            "Decapsulation should fail with mismatched keys"
        );
    }

    #[test]
    fn test_encapsulation_and_decapsulation_edge_case_context() {
        // Generate a key pair
        let keypair = KyberKeyPair::generate_key_pair().expect("Key generation failed");

        // Provide an empty context
        let context = b"";

        // Perform encapsulation
        let (shared_secret, ciphertext) =
            KyberKeyPair::encapsulate(&keypair.public_key, Some(context))
                .expect("Encapsulation failed");

        // Perform decapsulation with the same context
        let recovered_secret =
            KyberKeyPair::decapsulate(&keypair.private_key, &ciphertext, Some(context))
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


#[cfg(test)]
#[cfg(feature = "kyber")]
mod serialization_tests {
    use identity::{KyberKeyPair,PKITraits,KeySerialization};
    use fips203::traits::SerDes;

    #[test]
    fn test_serialization_and_deserialization() {
        let key_pair = KyberKeyPair::generate_key_pair().expect("Failed to generate key pair");
        let serialized = key_pair.to_bytes();

        let deserialized = KyberKeyPair::from_bytes(&serialized).expect("Failed to deserialize key pair");

        assert_eq!(key_pair.public_key.clone().into_bytes(), deserialized.public_key.clone().into_bytes());
        assert_eq!(key_pair.private_key.clone().into_bytes(), deserialized.private_key.clone().into_bytes());
    }

    #[test]
    fn test_invalid_deserialization() {
        let invalid_bytes = vec![0u8; 1000];
        let result = KyberKeyPair::from_bytes(&invalid_bytes);
        assert!(result.is_err());
    }
}
