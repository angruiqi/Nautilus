#[cfg(test)]
mod did_document_tests {
    use decentralized_identity::{KeyManager, Algorithm, DIDDocument};

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_did_document_generation_with_rsa() {
        let mut key_manager = KeyManager::new();
        let identity_suffix = "did:example";

        let key_id = format!("key-{}", uuid::Uuid::new_v4());
        let did_document = DIDDocument::new_with_keys(
            identity_suffix,
            key_id.clone(),
            &mut key_manager,
            Algorithm::RSA,
        );

        assert!(did_document.is_ok(), "Failed to create DIDDocument with RSA");
        let did_document = did_document.unwrap();

        assert_eq!(did_document.public_keys.len(), 1);
        assert_eq!(did_document.authentication.len(), 1);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_did_document_generation_with_ed25519() {
        let mut key_manager = KeyManager::new();
        let identity_suffix = "did:example";

        let key_id = format!("key-{}", uuid::Uuid::new_v4());
        let did_document = DIDDocument::new_with_keys(
            identity_suffix,
            key_id.clone(),
            &mut key_manager,
            Algorithm::Ed25519,
        );

        assert!(did_document.is_ok(), "Failed to create DIDDocument with Ed25519");
        let did_document = did_document.unwrap();

        assert_eq!(did_document.public_keys.len(), 1);
        assert_eq!(did_document.authentication.len(), 1);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_did_document_serialization() {
        let mut key_manager = KeyManager::new();
        let identity_suffix = "did:example";
        let key_id = format!("key-{}", uuid::Uuid::new_v4());
        let did_document = DIDDocument::new_with_keys(
            identity_suffix,
            key_id.clone(),
            &mut key_manager,
            Algorithm::Ed25519,
        )
        .expect("Failed to create DIDDocument");

        let serialized = serde_json::to_string(&did_document).expect("Serialization failed");
        let deserialized: DIDDocument =
            serde_json::from_str(&serialized).expect("Deserialization failed");

        assert_eq!(did_document.id, deserialized.id);
        assert_eq!(did_document.public_keys.len(), deserialized.public_keys.len());
    }
}
