use crate::{DIDDocument, VerifiableCredential, PublicKey, Proof};

#[derive(Debug)]
pub struct UserDocument {
    did_document: DIDDocument,
    credentials: Vec<VerifiableCredential>,
    verifying_key: PublicKey,
}

impl UserDocument {
    pub fn new(did_document: DIDDocument, verifying_key: PublicKey) -> Self {
        UserDocument {
            did_document,
            credentials: Vec::new(),
            verifying_key,
        }
    }

    pub fn add_credential(&mut self, credential: VerifiableCredential) {
        self.credentials.push(credential);
    }

    pub fn get_public_key_raw_bytes(&self) -> Vec<u8> {
        self.verifying_key.public_key_base64.clone().into_bytes()
    }

    pub fn get_did_document(&self) -> &DIDDocument {
        &self.did_document
    }

    pub fn add_proof_to_vc(&mut self, vc_id: &str, proof: Proof) -> Result<(), String> {
        if let Some(vc) = self.credentials.iter_mut().find(|vc| vc.id == vc_id) {
            vc.proof = proof;
            Ok(())
        } else {
            Err(format!("Verifiable Credential with ID {} not found", vc_id))
        }
    }

    pub fn display_vcs(&self) {
        println!("Verifiable Credentials:");
        for vc in &self.credentials {
            println!("ID: {}\nIssuer: {}\nSubject: {}\nProof: {:?}\nClaims: {:?}\n", 
                vc.id, vc.issuer, vc.subject, vc.proof, vc.credential_subject);
        }
    }
}
