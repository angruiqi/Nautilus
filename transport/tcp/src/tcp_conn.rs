use tokio::net::{TcpStream, TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use nautilus_core::connection::{
    Connection, ConnectionError, Transport, TransportListener, ConnectionEvent,
};
use nautilus_core::event_bus::EventBus;
use std::sync::Arc;
use tokio::sync::Mutex; // <-- use tokio's async Mutex
use crate::tcp_events::TcpEvent;
use socket2::Socket;

#[cfg(feature="framing")]
use nautilus_core::connection::framing::{Framing, FramingError};

// --- Tls-specific dependencies (optional) ---
#[cfg(feature="tls_layer")]
use tls::{TlsRecord, RecordType, TlsState};
#[cfg(feature="tls_layer")]
use handshake::Handshake;
#[cfg(feature="tls_layer")]
use std::sync::Mutex as StdMutex; // only needed if your TlsState is std::sync::Mutex

/// Our TCP connection struct can now be cloned because we store
/// the TcpStream in an Arc<Mutex<...>>.
#[derive(Debug, Clone)]
pub struct TcpConnection {
    /// Instead of `Option<TcpStream>`, store an Arc of a tokio::Mutex<Option<TcpStream>>.
    /// This lets us clone the entire connection object safely.
    stream: Arc<Mutex<Option<TcpStream>>>,
    conn_event_bus: Arc<EventBus<ConnectionEvent>>,
    tcp_event_bus: Arc<EventBus<TcpEvent>>,
}

impl TcpConnection {
    /// Create a new TCP connection object. Initially `stream` is None until connect().
    pub fn new(
        conn_event_bus: Arc<EventBus<ConnectionEvent>>,
        tcp_event_bus: Arc<EventBus<TcpEvent>>,
    ) -> Self {
        Self {
            stream: Arc::new(Mutex::new(None)),
            conn_event_bus,
            tcp_event_bus,
        }
    }

    /// Helper to publish generic connection events.
    async fn publish_conn_event(&self, event: ConnectionEvent) {
        self.conn_event_bus.publish(event).await;
    }

    /// Helper to publish TCP-specific events.
    async fn publish_tcp_event(&self, event: TcpEvent) {
        self.tcp_event_bus.publish(event).await;
    }

    /// (Optional) If you really need to "take" the stream out of the Arc,
    /// do so by locking and calling `take()`. But be careful: once taken,
    /// the next code to lock might see `None`.
    pub async fn take_stream(&self) -> Option<TcpStream> {
        let mut guard = self.stream.lock().await;
        guard.take()
    }
}

#[cfg(feature="framing")]
impl TcpConnection {
    pub async fn send_frame(&self, data: &[u8]) -> Result<(), ConnectionError> {
        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            let peer = stream
                .peer_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_default();

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
            Err(ConnectionError::SendFailed(
                "No active connection".to_string(),
            ))
        }
    }

    pub async fn receive_frame(&self) -> Result<Vec<u8>, ConnectionError> {
        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            let peer = stream
                .peer_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_default();

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
            Err(ConnectionError::ReceiveFailed(
                "No active connection".to_string(),
            ))
        }
    }
}

// --------------------------------------------------------------------
// TLS-SPECIFIC: Implement optional TLS handling
#[cfg(feature="tls_layer")]
impl TcpConnection {
    /// Perform a TLS handshake on top of the existing TCP stream...
    pub async fn upgrade_to_tls(
        &self,
        mut handshake: Handshake,
        state: Arc<StdMutex<TlsState>>, // or Arc<tokio::sync::Mutex<TlsState>> if you changed TlsState
    ) -> Result<(), ConnectionError> {
        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            let _final_bytes = handshake
                .execute(stream)
                .await
                .map_err(|e| ConnectionError::ConnectionFailed(e.to_string()))?;

            {
                let mut st = state.lock().map_err(|_| {
                    ConnectionError::Generic("StdMutex Poisoned".into())
                })?;
                st.set_handshake_complete(true);
            }

            // handshake done
            Ok(())
        } else {
            Err(ConnectionError::ConnectionFailed(
                "No active TCP stream".to_string(),
            ))
        }
    }

    /// Send data over TLS
    pub async fn tls_send(&self, data: &[u8], state: Arc<StdMutex<TlsState>>) -> Result<(), ConnectionError> {
        let session_key = {
            let st = state.lock().map_err(|_| ConnectionError::SendFailed("Mutex Poisoned".into()))?;
            st.session_key().to_vec()
        };
        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            let mut record = TlsRecord::new(RecordType::ApplicationData, data.to_vec());
            record.encrypt(&session_key).map_err(|e| ConnectionError::SendFailed(e.to_string()))?;

            stream
                .write_all(&record.serialize())
                .await
                .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;

            Ok(())
        } else {
            Err(ConnectionError::SendFailed(
                "No active connection".to_string(),
            ))
        }
    }

    /// Receive data over TLS
    pub async fn tls_receive(&self, state: Arc<StdMutex<TlsState>>) -> Result<Vec<u8>, ConnectionError> {
        let session_key = {
            let st = state.lock().map_err(|_| ConnectionError::ReceiveFailed("Mutex Poisoned".into()))?;
            st.session_key().to_vec()
        };

        let mut guard = self.stream.lock().await;
        if let Some(ref mut stream) = *guard {
            let mut buf = vec![0u8; 4096];
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;

            let mut record = TlsRecord::deserialize(&buf[..n])
                .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;
            let payload = record
                .decrypt(&session_key)
                .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;
            Ok(payload)
        } else {
            Err(ConnectionError::ReceiveFailed(
                "No active connection".to_string(),
            ))
        }
    }
}
// --------------------------------------------------------------------

#[async_trait]
impl Connection for TcpConnection {
    type Error = ConnectionError;

    async fn connect(&mut self, addr: &str) -> Result<(), Self::Error> {
        let mut retry_attempts = 0;
        const MAX_RETRIES: u8 = 5;
        let retry_interval = std::time::Duration::from_secs(2);

        loop {
            match TcpStream::connect(addr).await {
                Ok(stream) => {
                    // Convert Tokio TcpStream -> std::net::TcpStream
                    let std_stream = stream
                        .into_std()
                        .map_err(|e| ConnectionError::ConnectionFailed(e.to_string()))?;

                    // Use socket2 to enable TCP keep-alive
                    let socket = Socket::from(std_stream);
                    socket
                        .set_keepalive(Some(std::time::Duration::from_secs(60)).is_some())
                        .map_err(|e| ConnectionError::ConnectionFailed(e.to_string()))?;

                    // Convert back to Tokio TcpStream
                    let std_stream: std::net::TcpStream = socket.into();
                    std_stream
                        .set_nonblocking(true)
                        .map_err(|e| ConnectionError::ConnectionFailed(e.to_string()))?;

                    // Lock and store it in self.stream
                    let mut guard = self.stream.lock().await;
                    *guard = Some(TcpStream::from_std(std_stream).map_err(|e| {
                        ConnectionError::ConnectionFailed(e.to_string())
                    })?);

                    self.publish_conn_event(ConnectionEvent::Connected {
                        peer: addr.to_string(),
                    })
                    .await;
                    println!("Connected successfully!");
                    return Ok(());
                }
                Err(e) => {
                    if retry_attempts < MAX_RETRIES {
                        println!(
                            "Connection failed: {}. Retrying {}/{}",
                            e,
                            retry_attempts + 1,
                            MAX_RETRIES
                        );
                        retry_attempts += 1;
                        tokio::time::sleep(retry_interval).await;
                    } else {
                        self.publish_conn_event(ConnectionEvent::Error {
                            peer: addr.to_string(),
                            error: e.to_string(),
                        })
                        .await;
                        println!("Max retries reached. Giving up on connection.");
                        return Err(ConnectionError::ConnectionFailed(e.to_string()));
                    }
                }
            }
        }
    }

    async fn disconnect(&mut self) -> Result<(), Self::Error> {
        let mut guard = self.stream.lock().await;
        if let Some(stream) = guard.take() {
            let peer = stream
                .peer_addr()
                .map(|p| p.to_string())
                .unwrap_or_else(|_| "unknown".to_string());
            self.publish_conn_event(ConnectionEvent::Disconnected { peer }).await;
        }
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), Self::Error> {
        let peer;
        {
            // Lock, see if we have a stream
            let mut guard = self.stream.lock().await;
            if let Some(ref mut stream) = *guard {
                peer = stream
                    .peer_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_default();

                // Try writing
                if let Err(e) = stream.write_all(data).await {
                    self.publish_conn_event(ConnectionEvent::Error {
                        peer: peer.clone(),
                        error: e.to_string(),
                    })
                    .await;
                    println!("Send failed. Retrying...");

                    // Release the guard & try reconnect
                    guard.take();
                    drop(guard);
                    self.connect(&peer).await?;

                    // Now lock again & try to get the stream
                    let mut guard2 = self.stream.lock().await;
                    let stream2 = guard2
                        .as_mut()
                        .ok_or_else(|| ConnectionError::SendFailed("No stream after reconnect".into()))?;
                    stream2.write_all(data).await.map_err(|_| {
                        ConnectionError::SendFailed("Retry failed".to_string())
                    })?;
                }
            } else {
                return Err(ConnectionError::SendFailed(
                    "No active connection".to_string(),
                ));
            }
        }

        // Publish event after success
        self.publish_tcp_event(TcpEvent::DataSent {
            peer,
            data: data.to_vec(),
        })
        .await;
        Ok(())
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        loop {
            let mut guard = self.stream.lock().await;
            // If we have a stream, read from it
            if let Some(ref mut stream) = *guard {
                let peer = stream
                    .peer_addr()
                    .map(|addr| addr.to_string())
                    .unwrap_or_default();

                let mut buf = vec![0u8; 1024];
                match stream.read(&mut buf).await {
                    Ok(0) => {
                        println!("Connection closed by peer. Attempting reconnection...");
                        // Mark stream as None
                        guard.take();
                        drop(guard);
                        // Try reconnecting
                        self.connect(&peer).await?;
                        return Err(ConnectionError::ReceiveFailed(
                            "Peer disconnected".to_string(),
                        ));
                    }
                    Ok(n) => {
                        buf.truncate(n);
                        self.publish_tcp_event(TcpEvent::DataReceived {
                            peer: peer.clone(),
                            data: buf.clone(),
                        })
                        .await;
                        return Ok(buf);
                    }
                    Err(e) => {
                        // Error reading data; try again
                        self.publish_conn_event(ConnectionEvent::Error {
                            peer: peer.clone(),
                            error: e.to_string(),
                        })
                        .await;
                        println!("Error receiving data: {}, retrying...", e);
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                }
            } else {
                // No stream at all
                return Err(ConnectionError::ReceiveFailed(
                    "No active connection".to_string(),
                ));
            }
        }
    }

    fn is_connected(&self) -> bool {
        // Just check if the Option is Some
        if let Ok(guard) = self.stream.try_lock() {
            guard.is_some()
        } else {
            // If locked by someone else, assume connected
            true
        }
    }
}

/// Our TCP transport, storing shared event buses.
#[derive(Clone)]
pub struct TcpTransport {
    conn_event_bus: Arc<EventBus<ConnectionEvent>>,
    tcp_event_bus: Arc<EventBus<TcpEvent>>,
}

impl TcpTransport {
    pub fn new(
        conn_event_bus: Arc<EventBus<ConnectionEvent>>,
        tcp_event_bus: Arc<EventBus<TcpEvent>>,
    ) -> Self {
        Self {
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
        let (stream, _) = self
            .listener
            .accept()
            .await
            .map_err(|e| ConnectionError::ConnectionFailed(format!("Failed to accept: {}", e)))?;

        let peer = stream
            .peer_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "unknown".into());
        println!("Accepted a new connection from {}", peer);

        // Build a new TcpConnection with an empty "None" inside
        let connection = TcpConnection::new(
            Arc::clone(&self.conn_event_bus),
            Arc::clone(&self.tcp_event_bus),
        );

        // Lock its internal Option and store this newly-accepted stream
        {
            let mut guard = connection.stream.lock().await;
            *guard = Some(stream);
        }
        Ok(connection)
    }
}

impl TcpTransportListener {
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ConnectionError> {
        self.listener
            .local_addr()
            .map_err(|e| ConnectionError::ConnectionFailed(e.to_string()))
    }
}
