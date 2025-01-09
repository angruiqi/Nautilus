use std::thread;
use std::sync::{Arc, Mutex};
use decentralized_identity::{
    IdentityFlow, KeyManager, PKIFactory, Algorithm, Proof, UserDocument,
};
use base64::Engine;
use std::collections::HashMap;

fn main() {
    // Initialize a shared KeyManager
    let key_manager = Arc::new(Mutex::new(KeyManager::new()));

    // Configuration for the DID creation
    let identity_suffix = "did:example";
    let key_id = "key-main".to_string();
    let algorithm = Algorithm::Dilithium;

    // Clone the KeyManager for the thread
    let thread_key_manager = Arc::clone(&key_manager);

    // Create a thread to generate, sign the DID, and issue a VC
    let handle = thread::spawn(move || {
        // Lock the KeyManager to ensure thread-safe access
        let mut key_manager = thread_key_manager.lock().unwrap();

        // Create the DIDDocument
        let did_document_result = IdentityFlow::create_did_with_algorithm(
            identity_suffix,
            key_id.clone(),
            &mut key_manager,
            algorithm.clone(),
        );

        match did_document_result {
            Ok(did_document) => {
                println!("DID Document created successfully: {:?}", did_document);

                // Example of signing the DIDDocument
                let pki = PKIFactory::create_pki(algorithm).expect("Failed to create PKI");
                let signature = pki
                    .sign(did_document.id.as_bytes())
                    .expect("Failed to sign DID");

                println!(
                    "DID signed successfully with signature: {}",
                    base64::engine::general_purpose::STANDARD.encode(&signature)
                );

                // Verifying the signature
                let is_valid = pki
                    .verify(did_document.id.as_bytes(), &signature)
                    .expect("Failed to verify signature");

                if is_valid {
                    println!(
                        "Verified DID: {} with signature: {}",
                        did_document.id,
                        base64::engine::general_purpose::STANDARD.encode(signature.clone())
                    );

                    // Create a UserDocument and issue a Verifiable Credential
                    let public_key = did_document.public_keys[0].clone();
                    let mut user_document = UserDocument::new(did_document.clone(), public_key);

                    let mut claims = HashMap::new();
                    claims.insert("name".to_string(), "Alice".to_string());
                    claims.insert("email".to_string(), "alice@example.com".to_string());

                    let credential_id = "vc-1234".to_string();
                    let vc = decentralized_identity::VerifiableCredential::new(
                        credential_id.clone(),
                        did_document.id.clone(),
                        "did:example:recipient".to_string(),
                        None,
                        None,
                    );

                    let proof = Proof {
                        type_: "Ed25519Signature2020".to_string(),
                        created: chrono::Utc::now().to_rfc3339(),
                        proof_value: base64::engine::general_purpose::STANDARD.encode(signature),
                        verification_method: did_document.id.clone(),
                    };

                    user_document.add_credential(vc);
                    user_document.add_proof_to_vc(&credential_id, proof).unwrap();

                    // Display the UserDocument's Verifiable Credentials
                    user_document.display_vcs();
                    println!("Final Signed Document:\n{:#?}", user_document);
                } else {
                    eprintln!("Signature verification failed for DID: {}", did_document.id);
                }
            }
            Err(err) => {
                eprintln!("Failed to create DID Document: {}", err);
            }
        }
    });

    // Wait for the thread to complete
    handle.join().unwrap();

    println!("Main thread completed.");
}
