use decentralized_identity::{DIDDocument, KeyManager, Algorithm};
use uuid::Uuid;

/// Generates a DID document for a specific algorithm.
fn generate_did_for_algorithm(
    identity_suffix: &str,
    key_manager: &mut KeyManager,
    algorithm: Algorithm,
) -> Result<DIDDocument, String> {
    let key_id = format!("key-{}", Uuid::new_v4());
    println!("Generating DIDDocument for algorithm: {:?}", algorithm);

    let did_document = DIDDocument::new_with_keys(identity_suffix, key_id, key_manager, algorithm)
        .map_err(|e| format!("Failed to create DIDDocument: {:?}", e))?;

    Ok(did_document)
}

fn main() {
    let mut key_manager = KeyManager::new();
    let identity_suffix = "did:example";

    // Test RSA (feature-gated)
    #[cfg(feature = "pki_rsa")]
    {
        if let Ok(did_document) = generate_did_for_algorithm(identity_suffix, &mut key_manager, Algorithm::RSA) {
            println!("Generated DIDDocument for RSA: {:#?}", did_document);
        } else {
            eprintln!("Failed to generate DIDDocument for RSA");
        }
        println!("--------------------------------------------------");
    }

    // Test Dilithium (feature-gated)
    #[cfg(feature = "dilithium")]
    {
        if let Ok(did_document) = generate_did_for_algorithm(identity_suffix, &mut key_manager, Algorithm::Dilithium) {
            println!("Generated DIDDocument for Dilithium: {:#?}", did_document);
        } else {
            eprintln!("Failed to generate DIDDocument for Dilithium");
        }
        println!("--------------------------------------------------");
    }

    // Test Falcon (feature-gated)
    #[cfg(feature = "falcon")]
    {
        if let Ok(did_document) = generate_did_for_algorithm(identity_suffix, &mut key_manager, Algorithm::Falcon) {
            println!("Generated DIDDocument for Falcon: {:#?}", did_document);
        } else {
            eprintln!("Failed to generate DIDDocument for Falcon");
        }
        println!("--------------------------------------------------");
    }

    // Test Ed25519 (feature-gated)
    #[cfg(feature = "ed25519")]
    {
        if let Ok(did_document) = generate_did_for_algorithm(identity_suffix, &mut key_manager, Algorithm::Ed25519) {
            println!("Generated DIDDocument for Ed25519: {:#?}", did_document);
        } else {
            eprintln!("Failed to generate DIDDocument for Ed25519");
        }
        println!("--------------------------------------------------");
    }
}