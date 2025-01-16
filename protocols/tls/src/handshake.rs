// protocols\tls\src\handshake.rs
use async_trait::async_trait;
use handshake::{HandshakeStream,HandshakeError,HandshakeStep};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use futures::future::BoxFuture;

#[derive(Debug, Clone, Copy)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

pub struct HelloStep {
    protocol_id: String,
    role: HandshakeRole,
}

impl HelloStep {
    pub fn new(protocol_id: &str, role: HandshakeRole) -> Self {
        Self {
            protocol_id: protocol_id.to_string(),
            role,
        }
    }
}

#[async_trait]
impl HandshakeStep for HelloStep {
    fn get_protocol_id(&self) -> &str {
        &self.protocol_id
    }

    fn set_protocol_id(&mut self, _protocol_id: &str) {}

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            match self.role {
                HandshakeRole::Initiator => {
                    // Initiator sends "HELLO" and waits for "HELLO_ACK"
                    println!("[Initiator] Sending HELLO");
                    stream.write_all(b"HELLO").await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to send HELLO: {}", e))
                    })?;

                    println!("[Initiator] Waiting for HELLO_ACK");
                    let mut buf = [0u8; 9];
                    stream.read_exact(&mut buf).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to read HELLO_ACK: {}", e))
                    })?;

                    if &buf != b"HELLO_ACK" {
                        return Err(HandshakeError::Generic("Invalid HELLO_ACK response".into()));
                    }
                    println!("[Initiator] Received HELLO_ACK");

                    // Send AES key to responder
                    const AES_KEY: &[u8; 32] = b"my_secret_aes_key_32_bytes_long_";
                    println!("[Initiator] Sending AES key");
                    stream.write_all(AES_KEY).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to send AES key: {}", e))
                    })?;

                    Ok(AES_KEY.to_vec())
                }
                HandshakeRole::Responder => {
                    // Responder waits for "HELLO" and responds with "HELLO_ACK"
                    println!("[Responder] Waiting for HELLO");
                    let mut buf = [0u8; 5];
                    stream.read_exact(&mut buf).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to read HELLO: {}", e))
                    })?;

                    if &buf != b"HELLO" {
                        return Err(HandshakeError::Generic("Invalid HELLO response".into()));
                    }
                    println!("[Responder] Received HELLO");

                    println!("[Responder] Sending HELLO_ACK");
                    stream.write_all(b"HELLO_ACK").await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to send HELLO_ACK: {}", e))
                    })?;

                    // Receive AES key from initiator
                    let mut aes_key = [0u8; 32]; // Buffer for AES-128 key
                    println!("[Responder] Waiting for AES key");
                    stream.read_exact(&mut aes_key).await.map_err(|e| {
                        HandshakeError::Generic(format!("Failed to read AES key: {}", e))
                    })?;

                    println!("[Responder] Received AES key");
                    Ok(aes_key.to_vec())
                }
            }
        })
    }
}
pub struct CipherSuiteStep {
    protocol_id: String,
}

impl CipherSuiteStep {
    pub fn new(protocol_id: &str) -> Self {
        Self {
            protocol_id: protocol_id.to_string(),
        }
    }
}

#[async_trait]
impl HandshakeStep for CipherSuiteStep {
    fn get_protocol_id(&self) -> &str {
        &self.protocol_id
    }

    fn set_protocol_id(&mut self, protocol_id: &str) {
        self.protocol_id = protocol_id.to_string();
    }

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            // Send supported cipher suites
            stream.write_all(&input).await.map_err(|e| {
                HandshakeError::Generic(format!("Failed to send cipher suites: {}", e))
            })?;

            // Read the negotiated cipher suite
            let mut buf = vec![0; 1024];
            let n = stream.read(&mut buf).await.map_err(|e| {
                HandshakeError::Generic(format!("Failed to read cipher suite response: {}", e))
            })?;

            Ok(buf[..n].to_vec()) // Return the negotiated cipher suite
        })
    }
}