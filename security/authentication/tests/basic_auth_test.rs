#[cfg(test)]
mod tests {
    use authentication::hmac_auth::HmacAuthentication;
    use authentication::cmac_auth::CmacAuthentication;
    use authentication::hash_chain::HashChain;
    use authentication::traits::MessageAuthentication;

    const TEST_KEY: &[u8] = b"thisisexactly32byteslong12345678";
    const TEST_MESSAGE: &[u8] = b"The quick brown fox jumps over the lazy dog";

    // Test cases for HMAC
    mod hmac_tests {
        use super::*;

        #[test]
        fn test_hmac_sign_and_verify() {
            let hmac_auth = HmacAuthentication::new(TEST_KEY);

            let signature = hmac_auth.sign(TEST_MESSAGE);
            assert!(
                hmac_auth.verify(TEST_MESSAGE, &signature),
                "HMAC verification failed"
            );

            let invalid_signature = b"invalidsignature";
            assert!(
                !hmac_auth.verify(TEST_MESSAGE, invalid_signature),
                "HMAC should not verify an invalid signature"
            );
        }
    }

    // Test cases for CMAC
    mod cmac_tests {
        use super::*;

        #[test]
        fn test_cmac_sign_and_verify() {
            let cmac_auth = CmacAuthentication::new(TEST_KEY);
        
            let signature = cmac_auth.sign(TEST_MESSAGE);
            assert!(
                cmac_auth.verify(TEST_MESSAGE, &signature),
                "CMAC verification failed"
            );
        
            let invalid_signature = b"invalidsignature";
            assert!(
                !cmac_auth.verify(TEST_MESSAGE, invalid_signature),
                "CMAC should not verify an invalid signature"
            );
        }
    }

    // Test cases for Hash Chain
    mod hash_chain_tests {
        use super::*;

        #[test]
        fn test_hash_chain_generation_and_validation() {
            let seed = b"initial";
            let iterations = 5;
            let hash_chain = HashChain::new(seed, iterations);

            // Validate hashes at each index
            for i in 0..iterations {
                let expected_hash = &hash_chain.chain[i];
                assert!(
                    hash_chain.validate(i, expected_hash),
                    "HashChain validation failed at index {}",
                    i
                );
            }

            // Validation should fail for incorrect hashes
            let invalid_hash = b"notavalidhash";
            assert!(
                !hash_chain.validate(0, invalid_hash),
                "HashChain should not validate an invalid hash"
            );
        }
    }
}