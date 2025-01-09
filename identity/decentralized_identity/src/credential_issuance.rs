use crate::{DIDDocument, VerifiableCredential, PublicKey};
use chrono::{Utc, DateTime};
use std::collections::HashMap;

pub struct CredentialIssuer {
    pub did_document: DIDDocument,
    pub signing_key: PublicKey, // The signing key of the issuer
}

impl CredentialIssuer {
    pub fn new(did_document: DIDDocument, signing_key: PublicKey) -> Self {
        CredentialIssuer {
            did_document,
            signing_key,
        }
    }

    // Method to issue a Verifiable Credential
    pub fn issue_credential(
        &self,
        subject: String,
        credential_id: String,
        claims: HashMap<String, String>,
        vc_type: Option<Vec<String>>,
    ) -> VerifiableCredential {
        // Derive the issuer DID from the DIDDocument
        let issuer_did = self.did_document.id.clone();

        let mut vc = VerifiableCredential::new(
            credential_id,
            issuer_did,
            subject,
            vc_type, // Default or custom type
            None,    // Default proof_type
        );

        // Add claims to the credential
        for (key, value) in claims {
            vc.add_claim(key, value);
        }

        // Generate the proof
        let proof_value = self.sign_credential(&vc);
        let created: DateTime<Utc> = Utc::now();
        let verification_method = self
            .did_document
            .proof
            .as_ref()
            .map(|proof| proof.verification_method.clone())
            .unwrap_or_default();

        // Sign the credential
        vc.sign(proof_value, created.to_rfc3339(), verification_method);

        vc
    }

    // Example method to generate a proof (sign the credential)
    fn sign_credential(&self, _vc: &VerifiableCredential) -> String {
        "signature_placeholder".to_string()
    }
}
