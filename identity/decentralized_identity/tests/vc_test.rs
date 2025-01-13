#[cfg(test)]
mod credential_tests {
    use decentralized_identity::{Proof, VerifiableCredential};

    #[test]
    fn test_credential_creation() {
        let vc = VerifiableCredential::new(
            "vc-1".to_string(),
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            None,
            None,
        );

        assert_eq!(vc.id, "vc-1");
        assert_eq!(vc.issuer, "did:example:issuer");
        assert_eq!(vc.subject, "did:example:subject");
    }

    #[test]
    fn test_credential_proof() {
        let mut vc = VerifiableCredential::new(
            "vc-1".to_string(),
            "did:example:issuer".to_string(),
            "did:example:subject".to_string(),
            None,
            None,
        );

        let proof = Proof {
            type_: "Ed25519Signature2020".to_string(),
            created: "2023-01-01T00:00:00Z".to_string(),
            proof_value: "test-proof".to_string(),
            verification_method: "did:example:issuer".to_string(),
        };

        vc.sign(proof.proof_value.clone(), proof.created.clone(), proof.verification_method.clone());

        assert_eq!(vc.proof.proof_value, proof.proof_value);
    }
}
