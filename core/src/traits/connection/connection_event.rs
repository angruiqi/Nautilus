// core\src\traits\connection\connection_event.rs
#[derive(Debug, Clone)]
pub enum ConnectionEvent {
    Connected { peer: String },
    Disconnected { peer: String },
    Error { peer: String, error: String },
}