use std::collections::HashMap;
use crate::{DIDDocument, UserDocument,KeyType};
use crate::identity_error::IdentityError;

pub struct IdentityManager {
    pub storage: HashMap<String, UserDocument>, // In-memory storage for UserDocuments
}

impl IdentityManager {
    pub fn new() -> Self {
        IdentityManager {
            storage: HashMap::new(),
        }
    }

    pub fn save_user_document(&mut self, did_document: DIDDocument, verifying_key: String,key_type: KeyType) {
        let verifying_key = crate::PublicKey {
            id: verifying_key.clone(),
            type_: key_type,
            controller: did_document.id.clone(),
            public_key_base64: verifying_key,
        };

        let user_document = UserDocument::new(did_document.clone(), verifying_key);
        self.storage.insert(did_document.id.clone(), user_document);
    }

    pub fn remove_user_document(&mut self, did: &str) -> Result<UserDocument, IdentityError> {
        self.storage
            .remove(did)
            .ok_or_else(|| IdentityError::DocumentNotFound(did.to_string()))
    }

    pub fn get_user_document(&self, did: &str) -> Result<&UserDocument, IdentityError> {
        self.storage
            .get(did)
            .ok_or_else(|| IdentityError::DocumentNotFound(did.to_string()))
    }

    pub fn upsert_user_document(
      &mut self,
      did_document: DIDDocument,
      verifying_key: String,
      key_type: KeyType,
  ) {
      let verifying_key = crate::PublicKey {
          id: verifying_key.clone(),
          type_: key_type,
          controller: did_document.id.clone(),
          public_key_base64: verifying_key,
      };

      let user_document = UserDocument::new(did_document.clone(), verifying_key);
      self.storage.insert(did_document.id.clone(), user_document);
  }
}
