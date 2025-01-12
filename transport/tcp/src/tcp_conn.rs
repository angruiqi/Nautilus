// transport\tcp\src\tcp_conn.rs
use tokio::net::{TcpStream,TcpListener};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use async_trait::async_trait;
use nautilus_core::connection::{Connection, ConnectionError,Transport,TransportListener,ConnectionEvent};
use nautilus_core::event_bus::EventBus;
use std::sync::Arc;
use crate::tcp_events::TcpEvent;
#[cfg(feature = "secureconnection")]
use identity::{KyberKeyPair, KeyExchange};

#[cfg(feature = "secureconnection")]
mod secure_connection {
    use tokio::net::TcpStream;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use identity::{KyberKeyPair, KeyExchange};
    use data_encryption::{Aes256GcmEncryption, SymmetricEncryption};
    use nautilus_core::connection::ConnectionError;

    #[derive(Debug)]
    pub struct SecureModule {
        pub is_secure: bool,
        pub shared_secret: Option<Vec<u8>>,
        pub encryption: Option<Aes256GcmEncryption>,
    }

    impl SecureModule {
        pub fn new() -> Self {
            SecureModule {
                is_secure: false,
                shared_secret: None,
                encryption: None,
            }
        }

        pub fn set_shared_secret(&mut self, secret: Vec<u8>) -> Result<(), String> {
            self.shared_secret = Some(secret.clone());
            self.encryption = Some(Aes256GcmEncryption::new(secret, vec![0u8; 12])?);
            self.is_secure = true;
            Ok(())
        }

        pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
            if !self.is_secure {
                return Err("Connection is not secure".to_string());
            }
            self.encryption
                .as_ref()
                .ok_or("Encryption module is not initialized".to_string())?
                .encrypt(plaintext)
        }

        pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
            if !self.is_secure {
                return Err("Connection is not secure".to_string());
            }
            self.encryption
                .as_ref()
                .ok_or("Encryption module is not initialized".to_string())?
                .decrypt(ciphertext)
        }
        pub async fn perform_handshake(
            &mut self,
            stream: &mut TcpStream,
            local_keypair: KyberKeyPair,
            peer_public_key: Option<KyberKeyPair>,
            is_client: bool,
        ) -> Result<(), ConnectionError> {
            if is_client {
                // Client-side handshake
                if let Some(peer_keypair) = peer_public_key {
                    println!("Client: Performing key encapsulation...");
let (shared_secret, ciphertext) = KyberKeyPair::encapsulate(&peer_keypair.public_key, None)
    .map_err(|e| ConnectionError::Generic(format!("Key exchange failed: {}", e)))?;
println!("Client: Ciphertext length = {}", ciphertext.len());

println!("Client: Sending ciphertext...");
stream
    .write_all(&ciphertext)
    .await
    .map_err(|e| ConnectionError::SendFailed(e.to_string()))?;
        
                    self.set_shared_secret(shared_secret)
                        .map_err(|e| ConnectionError::Generic(e))?;
                    println!("Client handshake completed.");
                } else {
                    return Err(ConnectionError::Generic(
                        "Client requires peer public key for handshake.".to_string(),
                    ));
                }
            } else {
                // Server-side handshake
                println!("Server: Waiting for ciphertext...");
let mut buffer = vec![0u8; 1600]; // Update this to match the actual ciphertext size if needed
let size = stream
    .read_exact(&mut buffer)
    .await
    .map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;
println!("Server: Received ciphertext length = {}", size);

println!("Server: Performing key decapsulation...");
let shared_secret = KyberKeyPair::decapsulate(&local_keypair.private_key, &buffer, None)
    .map_err(|e| ConnectionError::Generic(format!("Key exchange failed: {}", e)))?;
        
                self.set_shared_secret(shared_secret)
                    .map_err(|e| ConnectionError::Generic(e))?;
                println!("Server handshake completed.");
            }
        
            Ok(())
        }
    }        
}

#[derive(Debug)]
pub struct TcpConnection {
    pub stream: Option<TcpStream>,
    conn_event_bus: Arc<EventBus<ConnectionEvent>>,
    tcp_event_bus: Arc<EventBus<TcpEvent>>,
    #[cfg(feature = "secureconnection")]
    secure_module: secure_connection::SecureModule,
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
            #[cfg(feature = "secureconnection")]
            secure_module: secure_connection::SecureModule::new(),
        }
    }

    async fn publish_conn_event(&self, event: ConnectionEvent) {
        self.conn_event_bus.publish(event).await;
    }

    async fn publish_tcp_event(&self, event: TcpEvent) {
        self.tcp_event_bus.publish(event).await;
    }


    #[cfg(feature = "secureconnection")]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ConnectionError> {
        self.secure_module
            .encrypt(plaintext)
            .map_err(|e| ConnectionError::Generic(e))
    }

    #[cfg(feature = "secureconnection")]
    pub fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ConnectionError> {
        self.secure_module
            .decrypt(ciphertext)
            .map_err(|e| ConnectionError::Generic(e))
    }
}
#[cfg(feature = "secureconnection")]
impl TcpConnection {
    pub async fn perform_handshake(
        &mut self,
        stream: &mut TcpStream,
        local_keypair: KyberKeyPair,
        peer_public_key: Option<KyberKeyPair>,
        is_client: bool,
    ) -> Result<(), ConnectionError> {
        self.secure_module
            .perform_handshake(stream, local_keypair, peer_public_key, is_client)
            .await
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
            Err(e) => Err(ConnectionError::ConnectionFailed(e.to_string())),
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
            stream.write_all(data).await.map_err(|e| ConnectionError::SendFailed(e.to_string()))
        } else {
            Err(ConnectionError::SendFailed("No active connection".to_string()))
        }
    }

    async fn receive(&mut self) -> Result<Vec<u8>, Self::Error> {
        if let Some(ref mut stream) = self.stream {
            let mut buffer = vec![0u8; 1024];
            stream.read_exact(&mut buffer).await.map_err(|e| ConnectionError::ReceiveFailed(e.to_string()))?;
            Ok(buffer)
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
        let (mut stream, addr) = self.listener.accept().await.map_err(|e| {
            ConnectionError::ConnectionFailed(format!("Failed to accept connection: {}", e))
        })?;

        // Notify that a connection has been established
        self.conn_event_bus.publish(ConnectionEvent::Connected { peer: addr.to_string() }).await;

        // Set up a new connection
        let mut connection = TcpConnection::new(
            Arc::clone(&self.conn_event_bus),
            Arc::clone(&self.tcp_event_bus),
        );
        connection.stream = Some(stream);
        Ok(connection)
    }
}


impl TcpTransportListener {
    pub fn local_addr(&self) -> Result<std::net::SocketAddr, ConnectionError> {
        self.listener.local_addr().map_err(|e|{
            ConnectionError::Generic(("Error getting Local Address").to_string())
        })
    }
}