#[cfg(test)]
mod key_manager_tests {
    use decentralized_identity::{KeyManager, Algorithm, PKIFactory};

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_key_manager_add_key_with_ed25519() {
        let mut key_manager = KeyManager::new();
        let algorithm = Algorithm::Ed25519;
        let key_id = "test-key".to_string();
        let pki = PKIFactory::create_pki(algorithm).expect("Failed to create PKI");

        key_manager.add_key(key_id.clone(), pki).expect("Failed to add key");
        assert!(key_manager.get_public_key(&key_id).is_ok());
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_key_manager_add_key_with_rsa() {
        let mut key_manager = KeyManager::new();
        let algorithm = Algorithm::RSA;
        let key_id = "test-key".to_string();
        let pki = PKIFactory::create_pki(algorithm).expect("Failed to create PKI");

        key_manager.add_key(key_id.clone(), pki).expect("Failed to add key");
        assert!(key_manager.get_public_key(&key_id).is_ok());
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_key_manager_get_private_key_with_rsa() {
        let mut key_manager = KeyManager::new();
        let algorithm = Algorithm::RSA;
        let key_id = "test-key".to_string();
        let pki = PKIFactory::create_pki(algorithm).expect("Failed to create PKI");

        key_manager.add_key(key_id.clone(), pki).expect("Failed to add key");
        assert!(key_manager.get_private_key(&key_id).is_ok());
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_key_manager_get_private_key_with_ed25519() {
        let mut key_manager = KeyManager::new();
        let algorithm = Algorithm::Ed25519;
        let key_id = "test-key".to_string();
        let pki = PKIFactory::create_pki(algorithm).expect("Failed to create PKI");

        key_manager.add_key(key_id.clone(), pki).expect("Failed to add key");
        assert!(key_manager.get_private_key(&key_id).is_ok());
    }
}