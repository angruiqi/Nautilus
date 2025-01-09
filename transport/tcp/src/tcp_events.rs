// transport\tcp\src\tcp_events.rs

// transport/tcp/src/tcp_event.rs
#[derive(Debug, Clone)]
pub enum TcpEvent {
    DataReceived { peer: String, data: Vec<u8> },
    DataSent { peer: String, data: Vec<u8> },
}
