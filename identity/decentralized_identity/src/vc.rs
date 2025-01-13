use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use crate::{Proof, IdentityError, PKI};
use chrono::Utc;
use base64::engine::general_purpose;
use base64::Engine as _; // For encoding

#[derive(Serialize, Deserialize, Debug,Clone)]
pub struct VerifiableCredential {
    pub id: String,
    pub issuer: String,
    pub subject: String,
    pub type_: Vec<String>,
    pub credential_subject: HashMap<String, String>,
    pub proof: Proof,
}

impl VerifiableCredential {
    pub fn new(
        id: String,
        issuer: String,
        subject: String,
        type_: Option<Vec<String>>,
        proof_type: Option<String>,
    ) -> Self {
        VerifiableCredential {
            id,
            issuer,
            subject,
            type_: type_.unwrap_or_else(|| vec!["VerifiableCredential".to_string()]),
            credential_subject: HashMap::new(),
            proof: Proof {
                type_: proof_type.unwrap_or_else(|| "EcdsaSignature2019".to_string()),
                created: "".to_string(),
                proof_value: "".to_string(),
                verification_method: "".to_string(),
            },
        }
    }

    pub fn add_claim(&mut self, key: String, value: String) {
        self.credential_subject.insert(key, value);
    }

    pub fn sign(&mut self, proof_value: String, created: String, verification_method: String) {
        self.proof.proof_value = proof_value;
        self.proof.created = created;
        self.proof.verification_method = verification_method;
    }

    pub fn issue_credential(
        issuer_did: &str,
        subject: String,
        credential_id: String,
        claims: HashMap<String, String>,
        pki: &PKI,
    ) -> Result<VerifiableCredential, IdentityError> {
        let mut vc = VerifiableCredential::new(
            credential_id,
            issuer_did.to_string(),
            subject,
            None, // Default type_
            None, // Default proof_type
        );

        // Add claims to the credential
        for (key, value) in claims {
            vc.add_claim(key, value);
        }

        // Generate the proof
        let proof_value = pki
            .sign(vc.id.as_bytes())
            .map_err(|e| IdentityError::Other(format!("Signing failed: {:?}", e)))?;
        let created = Utc::now().to_rfc3339();
        let verification_method = issuer_did.to_string();

        vc.sign(
            general_purpose::STANDARD.encode(proof_value),
            created,
            verification_method,
        );

        Ok(vc)
    }
}
