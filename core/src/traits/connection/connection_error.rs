// nautilus_core_proto\src\traits\connection_error_traits.rs
use std::fmt;


#[derive(Debug, Clone)]
pub enum ConnectionError {
    ConnectionFailed(String),
    SendFailed(String),
    ReceiveFailed(String),
    BindFailed(String),
    Generic(String),
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConnectionError::ConnectionFailed(msg) => write!(f, "Connection failed: {}", msg),
            ConnectionError::SendFailed(msg) => write!(f, "Send failed: {}", msg),
            ConnectionError::ReceiveFailed(msg) => write!(f, "Receive failed: {}", msg),
            ConnectionError::BindFailed(msg) => write!(f, "Bind failed: {}", msg),
            ConnectionError::Generic(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for ConnectionError {}

impl From<std::io::Error> for ConnectionError {
    fn from(err: std::io::Error) -> Self {
        ConnectionError::Generic(err.to_string())
    }
}