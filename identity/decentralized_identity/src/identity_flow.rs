use crate::{DIDDocument, Algorithm, PKIFactory, KeyManager};
use crate::identity_error::IdentityError;

pub struct IdentityFlow;

impl IdentityFlow {
    pub fn create_did_with_algorithm(
        identity_suffix: &str,
        key_id: String,
        key_manager: &mut KeyManager,
        algorithm: Algorithm,
    ) -> Result<DIDDocument, IdentityError> {
        DIDDocument::new_with_keys(identity_suffix, key_id, key_manager, algorithm)
    }

    pub fn add_key_to_did(
        did_document: &mut DIDDocument,
        key_id: String,
        key_manager: &mut KeyManager,
        algorithm: Algorithm,
    ) -> Result<(), IdentityError> {
        let pki = PKIFactory::create_pki(algorithm)?;
        key_manager.add_key(key_id.clone(), pki)?;
        did_document.add_public_key(key_manager.get_private_key(&key_id)?)
    }
}