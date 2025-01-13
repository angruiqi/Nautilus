#[cfg(test)]
mod user_document_tests {
    use decentralized_identity::{KeyManager, Algorithm, DIDDocument, VerifiableCredential, UserDocument};

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_user_document_add_credential_with_ed25519() {
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

        let public_key = did_document.public_keys[0].clone();
        let mut user_document = UserDocument::new(did_document, public_key);

        let credential = VerifiableCredential::new(
            "vc-1".to_string(),
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            None,
            None,
        );

        user_document.add_credential(credential);
        let user_document_credentials = user_document.get_credentials();
        assert_eq!(user_document_credentials.len(), 1);
    }

    #[cfg(feature = "ed25519")]
    #[test]
    fn test_user_document_serialization_with_ed25519() {
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

        let public_key = did_document.public_keys[0].clone();
        let user_document = UserDocument::new(did_document.clone(), public_key);
        let serialized = user_document.to_json().expect("Serialization failed");
        let deserialized: UserDocument =
            UserDocument::from_json(&serialized).expect("Deserialization failed");

        assert_eq!(user_document.did_document.id, deserialized.did_document.id);
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_user_document_add_credential_with_rsa() {
        let mut key_manager = KeyManager::new();
        let identity_suffix = "did:example";
        let key_id = format!("key-{}", uuid::Uuid::new_v4());
        let did_document = DIDDocument::new_with_keys(
            identity_suffix,
            key_id.clone(),
            &mut key_manager,
            Algorithm::RSA,
        )
        .expect("Failed to create DIDDocument");

        let public_key = did_document.public_keys[0].clone();
        let mut user_document = UserDocument::new(did_document, public_key);

        let credential = VerifiableCredential::new(
            "vc-1".to_string(),
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            None,
            None,
        );

        user_document.add_credential(credential);
        let user_document_credentials = user_document.get_credentials();
        assert_eq!(user_document_credentials.len(), 1);
    }

    #[cfg(feature = "pki_rsa")]
    #[test]
    fn test_user_document_serialization_with_rsa() {
        let mut key_manager = KeyManager::new();
        let identity_suffix = "did:example";
        let key_id = format!("key-{}", uuid::Uuid::new_v4());
        let did_document = DIDDocument::new_with_keys(
            identity_suffix,
            key_id.clone(),
            &mut key_manager,
            Algorithm::RSA,
        )
        .expect("Failed to create DIDDocument");

        let public_key = did_document.public_keys[0].clone();
        let user_document = UserDocument::new(did_document.clone(), public_key);
        let serialized = user_document.to_json().expect("Serialization failed");
        let deserialized: UserDocument =
            UserDocument::from_json(&serialized).expect("Deserialization failed");

        assert_eq!(user_document.did_document.id, deserialized.did_document.id);
    }
}
