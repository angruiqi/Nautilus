use crate::{DIDDocument, VerifiableCredential, PublicKey, KeyManager, IdentityError};
use chrono::{Utc, DateTime};
use std::collections::HashMap;
use base64::engine::general_purpose;
use base64::Engine as _;

pub struct CredentialIssuer {
    pub did_document: DIDDocument,
    pub signing_key: PublicKey, // The signing public key of the issuer
    pub key_manager: KeyManager, // Key manager to retrieve private key
}

impl CredentialIssuer {
    pub fn new(did_document: DIDDocument, signing_key: PublicKey, key_manager: KeyManager) -> Self {
        CredentialIssuer {
            did_document,
            signing_key,
            key_manager,
        }
    }

    // Method to issue a Verifiable Credential
    pub fn issue_credential(
        &self,
        subject: String,
        credential_id: String,
        claims: HashMap<String, String>,
        vc_type: Option<Vec<String>>,
    ) -> Result<VerifiableCredential, IdentityError> {
        // Derive the issuer DID from the DIDDocument
        let issuer_did = self.did_document.id.clone();

        let mut vc = VerifiableCredential::new(
            credential_id,
            issuer_did,
            subject,
            vc_type, 
            Some(self.signing_key.type_.to_string()),  // Use explicit proof type based on key type
        );

        // Add claims to the credential
        for (key, value) in claims {
            vc.add_claim(key, value);
        }

        // Generate the proof
        let proof_value = self.sign_credential(&vc)?;
        let created: DateTime<Utc> = Utc::now();
        let verification_method = self
            .did_document
            .proof
            .as_ref()
            .map(|proof| proof.verification_method.clone())
            .unwrap_or_else(|| format!("{}-Anonymous", self.did_document.id));

        // Sign the credential
        vc.sign(proof_value, created.to_rfc3339(), verification_method);

        Ok(vc)
    }

    // Method to sign the credential using the public key's corresponding private key
    fn sign_credential(&self, vc: &VerifiableCredential) -> Result<String, IdentityError> {
        let key_id = &self.signing_key.id;

        // Retrieve the private key using the key manager
        let private_key = self.key_manager.get_private_key(key_id)?;

        // Perform signing operation
        let signature = private_key
            .sign(vc.id.as_bytes())
            .map_err(|_| IdentityError::Other("Signing failed".to_string()))?;

        Ok(general_purpose::STANDARD.encode(signature))
    }
}
