// use negotiation::{CipherSuite, NegoServer, NegoClient, Negotiation};
// use tokio::sync::{mpsc, Mutex};
// use std::sync::Arc;
// use negotiation::MockConnection;
// #[tokio::test]
// async fn test_successful_negotiation() {
//     let supported_suites = vec![
//         CipherSuite::Aes256GcmSha384,
//         CipherSuite::ChaCha20Poly1305Sha256,
//     ];
//     let available_suites = vec![
//         CipherSuite::ChaCha20Poly1305Sha256,
//         CipherSuite::EcdhNistP256AesGcm,
//     ];

//     // Create mock communication channels
//     let (client_to_server_tx, client_to_server_rx) = mpsc::channel(100);
//     let (server_to_client_tx, server_to_client_rx) = mpsc::channel(100);

//     // Mock connection for client and server
//     let client_connection = Arc::new(Mutex::new(MockConnection::new(
//         client_to_server_tx,
//         server_to_client_rx,
//     )));
//     let server_connection = Arc::new(Mutex::new(MockConnection::new(
//         server_to_client_tx,
//         client_to_server_rx,
//     )));

//     // Initialize client and server
//     let mut client = NegoClient {
//         supported_cipher_suites: supported_suites.clone(),
//         connection: client_connection.clone(),
//     };

//     let mut server = NegoServer {
//         available_cipher_suites: available_suites.clone(),
//         connection: server_connection.clone(),
//     };

//     // Run negotiation tasks
//     let server_task = tokio::spawn(async move {
//         server.negotiate().await.expect("Server negotiation failed")
//     });

//     let client_task = tokio::spawn(async move {
//         client.negotiate().await.expect("Client negotiation failed")
//     });

//     let (server_result, client_result) = tokio::join!(server_task, client_task);

//     assert!(server_result.is_ok());
//     assert!(client_result.is_ok());

//     // Print the shared secret
//     if let (Ok(server_negotiation), Ok(client_negotiation)) = (server_result, client_result) {
//         println!(
//             "Shared Secret (Server): {:?}",
//             server_negotiation.shared_secret
//         );
//         println!(
//             "Shared Secret (Client): {:?}",
//             client_negotiation.shared_secret
//         );
//         assert_eq!(
//             server_negotiation.shared_secret,
//             client_negotiation.shared_secret,
//             "Shared secrets do not match"
//         );
//     }
// }
