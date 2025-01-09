use async_trait::async_trait;
use std::error::Error;
use std::fmt;
use nautilus_core::connection::Connection;

// Define a custom error type
#[derive(Debug)]
struct MockError(String);

impl fmt::Display for MockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Error for MockError {}

// Mock implementation of the `Connection` trait
struct MockConnection {
    connected: bool,
}

#[async_trait]
impl Connection for MockConnection {
    type Error = MockError;

    async fn connect(&mut self, _: &str) -> Result<(), Self::Error> {
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> Result<(), Self::Error> {
        self.connected = false;
        Ok(())
    }

    async fn send(&mut self, _: &[u8]) -> Result<(), Self::Error> {
        if self.connected {
            Ok(())
        } else {
            Err(MockError("Not connected".to_string()))
        }
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        if self.connected {
            Ok(vec![1, 2, 3])
        } else {
            Err(MockError("Not connected".to_string()))
        }
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[tokio::test]
async fn test_mock_connection() {
    let mut connection = MockConnection { connected: false };

    // Test connection
    assert!(!connection.is_connected());
    connection.connect("127.0.0.1").await.unwrap();
    assert!(connection.is_connected());

    // Test sending data
    connection.send(b"test data").await.unwrap();

    // Test receiving data
    let data = connection.receive().await.unwrap();
    assert_eq!(data, vec![1, 2, 3]);

    // Test disconnecting
    connection.disconnect().await.unwrap();
    assert!(!connection.is_connected());
}