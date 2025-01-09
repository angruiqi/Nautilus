// transport\tcp\src\tcp_conn.rs
use tokio::net::{TcpStream,TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use nautilus_core::connection::{Connection, ConnectionError,Transport,TransportListener,ConnectionEvent};
use nautilus_core::event_bus::EventBus;
use std::sync::Arc;
use crate::tcp_events::TcpEvent;

#[cfg(feature="framing")]
use nautilus_core::connection::framing::{Framing,FramingError};
#[derive(Debug)]
pub struct TcpConnection {
    stream: Option<TcpStream>,
    conn_event_bus: Arc<EventBus<ConnectionEvent>>, // EventBus for generic connection events
    tcp_event_bus: Arc<EventBus<TcpEvent>>,        // EventBus for TCP-specific events
}
impl TcpConnection {
    pub fn new(
        conn_event_bus: Arc<EventBus<ConnectionEvent>>,
        tcp_event_bus: Arc<EventBus<TcpEvent>>,
    ) -> Self {
        TcpConnection {
            stream: None,
            conn_event_bus,
            tcp_event_bus,
        }
    }

    async fn publish_conn_event(&self, event: ConnectionEvent) {
        self.conn_event_bus.publish(event).await;
    }

    async fn publish_tcp_event(&self, event: TcpEvent) {
        self.tcp_event_bus.publish(event).await;
    }
}
#[cfg(feature="framing")]
impl TcpConnection{
    pub async fn send_frame(&mut self, data: &[u8]) -> Result<(), ConnectionError> {
        if let Some(ref mut stream) = self.stream {
            let peer = stream.peer_addr().map(|addr| addr.to_string()).unwrap_or_default();

            // Write length header
            let length = (data.len() as u32).to_be_bytes();
            if let Err(e) = stream.write_all(&length).await {
                self.publish_conn_event(ConnectionEvent::Error {
                    peer: peer.clone(),
                    error: e.to_string(),
                })
                .await;
                return Err(ConnectionError::SendFailed(e.to_string()));
            }

            // Write data
            if let Err(e) = stream.write_all(data).await {
                self.publish_conn_event(ConnectionEvent::Error {
                    peer: peer.clone(),
                    error: e.to_string(),
                })
                .await;
                return Err(ConnectionError::SendFailed(e.to_string()));
            }

            self.publish_tcp_event(TcpEvent::DataSent {
                peer,
                data: data.to_vec(),
            })
            .await;

            Ok(())
        } else {
            Err(ConnectionError::SendFailed("No active connection".to_string()))
        }
    }

        pub async fn receive_frame(&mut self) -> Result<Vec<u8>, ConnectionError> {
        if let Some(ref mut stream) = self.stream {
            let peer = stream.peer_addr().map(|addr| addr.to_string()).unwrap_or_default();

            // Read length header
            let mut length_buf = [0u8; 4];
            if let Err(e) = stream.read_exact(&mut length_buf).await {
                self.publish_conn_event(ConnectionEvent::Error {
                    peer: peer.clone(),
                    error: e.to_string(),
                })
                .await;
                return Err(ConnectionError::ReceiveFailed(e.to_string()));
            }

            let length = u32::from_be_bytes(length_buf) as usize;

            // Read payload
            let mut payload = vec![0u8; length];
            if let Err(e) = stream.read_exact(&mut payload).await {
                self.publish_conn_event(ConnectionEvent::Error {
                    peer: peer.clone(),
                    error: e.to_string(),
                })
                .await;
                return Err(ConnectionError::ReceiveFailed(e.to_string()));
            }

            self.publish_tcp_event(TcpEvent::DataReceived {
                peer,
                data: payload.clone(),
            })
            .await;

            Ok(payload)
        } else {
            Err(ConnectionError::ReceiveFailed("No active connection".to_string()))
        }
    }
}

#[async_trait]
impl Connection for TcpConnection {
    type Error = ConnectionError;

    async fn connect(&mut self, addr: &str) -> Result<(), Self::Error> {
        match TcpStream::connect(addr).await {
            Ok(stream) => {
                self.stream = Some(stream);
                self.publish_conn_event(ConnectionEvent::Connected { peer: addr.to_string() }).await;
                Ok(())
            }
            Err(e) => {
                self.publish_conn_event(ConnectionEvent::Error {
                    peer: addr.to_string(),
                    error: e.to_string(),
                })
                .await;
                Err(ConnectionError::ConnectionFailed(e.to_string()))
            }
        }
    }

    async fn disconnect(&mut self) -> Result<(), Self::Error> {
        if let Some(stream) = self.stream.take() {
            let peer = stream.peer_addr().unwrap().to_string();
            self.publish_conn_event(ConnectionEvent::Disconnected { peer }).await;
        }
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        if let Some(ref mut stream) = self.stream {
            // Clone the peer address to avoid conflicts
            let peer = stream.peer_addr().map(|addr| addr.to_string()).unwrap_or_default();
    
            // Attempt to write data
            if let Err(e) = stream.write_all(data).await {
                self.publish_conn_event(ConnectionEvent::Error {
                    peer: peer.clone(),
                    error: e.to_string(),
                })
                .await;
                return Err(ConnectionError::SendFailed(e.to_string()));
            }
    
            // Publish the data sent event
            self.publish_tcp_event(TcpEvent::DataSent {
                peer,
                data: data.to_vec(),
            })
            .await;
    
            Ok(())
        } else {
            Err(ConnectionError::SendFailed("No active connection".to_string()))
        }
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        let mut buf = vec![0u8; 1024];
        if let Some(ref mut stream) = self.stream {
            // Clone peer address to avoid conflicting borrows
            let peer = stream.peer_addr().map(|addr| addr.to_string()).unwrap_or_default();
    
            // Attempt to read data
            let n = match stream.read(&mut buf).await {
                Ok(n) => n,
                Err(e) => {
                    self.publish_conn_event(ConnectionEvent::Error {
                        peer: peer.clone(),
                        error: e.to_string(),
                    })
                    .await;
                    return Err(ConnectionError::ReceiveFailed(e.to_string()));
                }
            };
    
            buf.truncate(n);
    
            // Publish the data received event
            self.publish_tcp_event(TcpEvent::DataReceived {
                peer,
                data: buf.clone(),
            })
            .await;
    
            Ok(buf)
        } else {
            Err(ConnectionError::ReceiveFailed("No active connection".to_string()))
        }
    }
    fn is_connected(&self) -> bool {
        self.stream.is_some()
    }
}

#[derive(Clone)]
pub struct TcpTransport {
    conn_event_bus: Arc<EventBus<ConnectionEvent>>, // EventBus for generic connection events
    tcp_event_bus: Arc<EventBus<TcpEvent>>,        // EventBus for TCP-specific events
}

impl TcpTransport {
    pub fn new(
        conn_event_bus: Arc<EventBus<ConnectionEvent>>,
        tcp_event_bus: Arc<EventBus<TcpEvent>>,
    ) -> Self {
        TcpTransport {
            conn_event_bus,
            tcp_event_bus,
        }
    }
}

#[async_trait]
impl Transport for TcpTransport {
    type Connection = TcpConnection;
    type Listener = TcpTransportListener;
    type Error = ConnectionError;

    async fn listen(&self, addr: &str) -> Result<Self::Listener, Self::Error> {
        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| ConnectionError::BindFailed(e.to_string()))?;
        Ok(TcpTransportListener {
            listener,
            conn_event_bus: Arc::clone(&self.conn_event_bus),
            tcp_event_bus: Arc::clone(&self.tcp_event_bus),
        })
    }

    async fn dial(&self, addr: &str) -> Result<Self::Connection, Self::Error> {
        let mut connection = TcpConnection::new(
            Arc::clone(&self.conn_event_bus),
            Arc::clone(&self.tcp_event_bus),
        );
        connection.connect(addr).await?;
        Ok(connection)
    }
}

pub struct TcpTransportListener {
    listener: TcpListener,
    conn_event_bus: Arc<EventBus<ConnectionEvent>>,
    tcp_event_bus: Arc<EventBus<TcpEvent>>,
}

#[async_trait]
impl TransportListener<TcpConnection, ConnectionError> for TcpTransportListener {
    async fn accept(&mut self) -> Result<TcpConnection, ConnectionError> {
        let (_stream, _) = self.listener.accept().await.map_err(|e| {
            ConnectionError::ConnectionFailed(format!("Failed to accept connection: {}", e))
        })?;
        Ok(TcpConnection::new(
            Arc::clone(&self.conn_event_bus),
            Arc::clone(&self.tcp_event_bus),
        ))
    }
}




