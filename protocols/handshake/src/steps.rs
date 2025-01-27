use crate::traits::{HandshakeStep, HandshakeStream};
use crate::handshake_error::HandshakeError;
use tokio::io::{AsyncWriteExt, AsyncReadExt};
use futures::future::BoxFuture;

/// Node Hello step
pub struct NodeHello {
    protocol_id: Option<String>,
}

impl NodeHello {
    pub fn new() -> Self {
        Self { protocol_id: None }
    }
}

impl HandshakeStep for NodeHello {
    fn get_protocol_id(&self) -> &str {
        self.protocol_id.as_deref().unwrap_or("")
    }

    fn set_protocol_id(&mut self, protocol_id: &str) {
        self.protocol_id = Some(protocol_id.to_string());
    }

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        _input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            // Send "HELLO"
            stream
                .write_all(b"HELLO")
                .await
                .map_err(|e| HandshakeError::Generic(e.to_string()))?;
            println!("N1 -> N2: Sending HELLO");

            // Return an empty Vec<u8> or some data
            Ok(vec![])
        })
    }
}

/// Hello Response step
pub struct HelloResponse {
    protocol_id: Option<String>,
}

impl HelloResponse {
    pub fn new() -> Self {
        Self { protocol_id: None }
    }
}

impl HandshakeStep for HelloResponse {
    fn get_protocol_id(&self) -> &str {
        self.protocol_id.as_deref().unwrap_or("")
    }

    fn set_protocol_id(&mut self, protocol_id: &str) {
        self.protocol_id = Some(protocol_id.to_string());
    }

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        _input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            let mut buffer = [0u8; 5];
            stream
                .read_exact(&mut buffer)
                .await
                .map_err(|e| HandshakeError::Generic(e.to_string()))?;
            if &buffer == b"HELLO" {
                println!("N1 <- N2: Receiving HELLO");
                Ok(vec![])
            } else {
                Err(HandshakeError::Generic(
                    "Unexpected response".to_string(),
                ))
            }
        })
    }
}

/// Cipher Suite Exchange step
pub struct CipherSuiteExchange {
    protocol_id: Option<String>,
}

impl CipherSuiteExchange {
    pub fn new() -> Self {
        Self { protocol_id: None }
    }
}

impl HandshakeStep for CipherSuiteExchange {
    fn get_protocol_id(&self) -> &str {
        self.protocol_id.as_deref().unwrap_or("")
    }

    fn set_protocol_id(&mut self, protocol_id: &str) {
        self.protocol_id = Some(protocol_id.to_string());
    }

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        _input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            // Send "CIPHERSUITES"
            stream
                .write_all(b"CIPHERSUITES")
                .await
                .map_err(|e| HandshakeError::NegotiationFailed(e.to_string()))?;
            println!("N1 -> N2: Exchanging Cipher Suites");
            // Return some data so that next step sees it
            Ok(b"CIPHER_ACK".to_vec())
        })
    }
}

/// Cipher Suite Acknowledgment step
pub struct CipherSuiteAck {
    protocol_id: Option<String>,
}

impl CipherSuiteAck {
    pub fn new() -> Self {
        Self { protocol_id: None }
    }
}

impl HandshakeStep for CipherSuiteAck {
    fn get_protocol_id(&self) -> &str {
        self.protocol_id.as_deref().unwrap_or("")
    }

    fn set_protocol_id(&mut self, protocol_id: &str) {
        self.protocol_id = Some(protocol_id.to_string());
    }

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            // Read a response
            let mut buffer = vec![0; 1024];
            let n = stream
                .read(&mut buffer)
                .await
                .map_err(|e| HandshakeError::NegotiationFailed(e.to_string()))?;
            let received = std::str::from_utf8(&buffer[..n])
                .map_err(|e| HandshakeError::Generic(e.to_string()))?;
            println!("N1 <- N2: Acknowledging Cipher Suites: {}", received);

            // Maybe return input unchanged
            Ok(input)
        })
    }
}

// Example custom step
pub struct CustomProtocolStep {
    protocol_id: Option<String>,
}

impl CustomProtocolStep {
    pub fn new() -> Self {
        Self { protocol_id: None }
    }
}

impl HandshakeStep for CustomProtocolStep {
    fn get_protocol_id(&self) -> &str {
        self.protocol_id.as_deref().unwrap_or("")
    }

    fn set_protocol_id(&mut self, protocol_id: &str) {
        self.protocol_id = Some(protocol_id.to_string());
    }

    fn execute<'a>(
        &'a mut self,
        stream: &'a mut dyn HandshakeStream,
        _input: Vec<u8>,
    ) -> BoxFuture<'a, Result<Vec<u8>, HandshakeError>> {
        Box::pin(async move {
            stream
                .write_all(b"CUSTOM_STEP")
                .await
                .map_err(|e| HandshakeError::Generic(e.to_string()))?;
            println!("CustomProtocolStep executed.");
            // Return empty or some data
            Ok(vec![])
        })
    }
}
