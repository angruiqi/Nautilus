// identity\decentralized_identity\examples\decentralized_identity.rs
use decentralized_identity::{DIDDocument, KeyManager, Algorithm};
use uuid::Uuid;

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

    // Define the algorithms to test
    let algorithms = vec![
        Algorithm::RSA,
        Algorithm::Dilithium,
        Algorithm::Falcon,
        Algorithm::Ed25519,
    ];

    for algorithm in algorithms {
        match generate_did_for_algorithm(identity_suffix, &mut key_manager, algorithm) {
            Ok(did_document) => {
                println!("Generated DIDDocument: {:#?}", did_document);
            }
            Err(err) => {
                eprintln!("Error: {}", err);
            }
        }
        println!("--------------------------------------------------");
    }
}
