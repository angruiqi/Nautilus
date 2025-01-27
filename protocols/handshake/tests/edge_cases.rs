#[cfg(test)]
mod edge_case_testing {
    use tokio::net::{TcpListener, TcpStream};
    use handshake::{
        Handshake, NodeHello, HelloResponse, CipherSuiteExchange, CustomProtocolStep,
    };

    #[tokio::test]
    async fn test_missing_protocol_id() {
        let server = tokio::spawn(async {
            let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new())); // Protocol A
            handshake.add_step(Box::new(HelloResponse::new())); // Protocol A
            handshake.add_step(Box::new(CustomProtocolStep::new())); // No Protocol ID

            let result = handshake.execute(&mut stream).await;
            assert!(
                result.is_err(),
                "Server should fail due to step without protocol ID"
            );
        });

        let client = tokio::spawn(async {
            let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new()));
            handshake.add_step(Box::new(HelloResponse::new()));
            handshake.add_step(Box::new(CustomProtocolStep::new()));

            let result = handshake.execute(&mut stream).await;
            assert!(
                result.is_err(),
                "Client should fail due to step without protocol ID"
            );
        });

        let _ = tokio::join!(server, client);
    }

    #[tokio::test]
    async fn test_protocol_id_mismatch() {
        let server = tokio::spawn(async {
            let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new()));
            handshake.add_step(Box::new(HelloResponse::new()));
            handshake.add_step(Box::new(CipherSuiteExchange::new())); // Protocol A

            let result = handshake.execute(&mut stream).await;
            assert!(
                result.is_ok(),
                "Server handshake should pass even with mismatched client protocol ID"
            );
        });

        let client = tokio::spawn(async {
            let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

            let mut handshake = Handshake::new("protocol_b"); // Different protocol ID
            handshake.add_step(Box::new(NodeHello::new()));
            handshake.add_step(Box::new(HelloResponse::new()));
            handshake.add_step(Box::new(CipherSuiteExchange::new()));

            let result = handshake.execute(&mut stream).await;
            assert!(
                result.is_err(),
                "Client handshake should fail due to protocol ID mismatch"
            );
        });

        let _ = tokio::join!(server, client);
    }

    #[tokio::test]
    async fn test_partial_step_execution() {
        let server = tokio::spawn(async {
            let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new()));
            handshake.add_step(Box::new(HelloResponse::new()));

            let result = handshake.execute(&mut stream).await;
            assert!(
                result.is_ok(),
                "Server handshake should succeed with partial steps"
            );
        });

        let client = tokio::spawn(async {
            let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new()));

            let result = handshake.execute(&mut stream).await;
            assert!(
                result.is_ok(),
                "Client handshake should succeed with partial steps"
            );
        });

        let _ = tokio::join!(server, client);
    }
}
