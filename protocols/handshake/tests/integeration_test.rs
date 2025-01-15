#[cfg(test)]
mod complex_handshake_test {
    use tokio::net::{TcpListener, TcpStream};
    use handshake::{
        Handshake, NodeHello, HelloResponse, CipherSuiteExchange,HandshakeError,HandshakeStream, HandshakeStep,
    };
    use tokio::io::{AsyncWriteExt,AsyncReadExt};
    use futures::future::BoxFuture;
    

    pub struct EncryptedDataExchange {
      protocol_id: String,
  }
  
  impl EncryptedDataExchange {
      pub fn new(protocol_id: &str) -> Self {
          Self {
              protocol_id: protocol_id.to_string(),
          }
      }
  }
  
  impl HandshakeStep for EncryptedDataExchange {
      fn get_protocol_id(&self) -> &str {
          &self.protocol_id
      }
  
      fn set_protocol_id(&mut self, protocol_id: &str) {
          self.protocol_id = protocol_id.to_string();
      }
  
      fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        _: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            // Simulating encryption key exchange
            let encryption_key = b"ENCRYPTED_KEY"; // Length is 13
            stream
                .write_all(encryption_key)
                .await
                .map_err(|e| HandshakeError::Generic(e.to_string()))?;
            println!("N1 -> N2: Sending encryption key");

            let mut buffer = [0u8; 13]; // Match the length of encryption_key
            stream
                .read_exact(&mut buffer)
                .await
                .map_err(|e| HandshakeError::Generic(e.to_string()))?;
            if &buffer == encryption_key {
                println!("N1 <- N2: Encryption key exchange confirmed");
                Ok(vec![])
            } else {
                Err(HandshakeError::NegotiationFailed(
                    "Encryption key mismatch".to_string(),
                ))
            }
        })
    }
  }

    #[tokio::test]
    async fn test_complex_handshake() {
        let server = tokio::spawn(async {
            let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
            let (mut stream, _) = listener.accept().await.unwrap();

            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new()));
            handshake.add_step(Box::new(HelloResponse::new()));
            handshake.add_step(Box::new(CipherSuiteExchange::new()));
            handshake.add_step(Box::new(EncryptedDataExchange::new("protocol_a")));

            let result = handshake.execute(&mut stream).await;
            assert!(result.is_ok(), "Server handshake failed: {:?}", result);
        });

        let client = tokio::spawn(async {
            let mut stream = TcpStream::connect("127.0.0.1:8080").await.unwrap();

            let mut handshake = Handshake::new("protocol_a");
            handshake.add_step(Box::new(NodeHello::new()));
            handshake.add_step(Box::new(HelloResponse::new()));
            handshake.add_step(Box::new(CipherSuiteExchange::new()));
            handshake.add_step(Box::new(EncryptedDataExchange::new("protocol_a")));

            let result = handshake.execute(&mut stream).await;
            assert!(result.is_ok(), "Client handshake failed: {:?}", result);
        });

        let _ = tokio::join!(server, client);
    }
}
