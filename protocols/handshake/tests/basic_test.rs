#[cfg(test)]
mod basic_testing {
    use tokio::net::{TcpListener, TcpStream};
    use handshake::{Handshake, NodeHello, HelloResponse, CipherSuiteExchange, CipherSuiteAck};


    #[tokio::test]
    async fn test_basic_handshake() {
        // Run a mock server
        let server = tokio::spawn(async {
            let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new()));
            handshake.add_step(Box::new(HelloResponse::new()));
            handshake.add_step(Box::new(CipherSuiteExchange::new()));
            handshake.add_step(Box::new(CipherSuiteAck::new()));

            let result = handshake.execute(&mut stream).await;
            assert!(result.is_ok(), "Server handshake failed: {:?}", result);
        });

        // Run a mock client
        let client = tokio::spawn(async {
            let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new()));
            handshake.add_step(Box::new(HelloResponse::new()));
            handshake.add_step(Box::new(CipherSuiteExchange::new()));
            handshake.add_step(Box::new(CipherSuiteAck::new()));

            let result = handshake.execute(&mut stream).await;
            assert!(result.is_ok(), "Client handshake failed: {:?}", result);
        });

        let _ = tokio::join!(server, client);
    }
}
