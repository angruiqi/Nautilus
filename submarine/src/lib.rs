use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};
use tcp::{TcpTransport, TcpConnection, TcpEvent};
use nautilus_core::connection::{Connection, Transport, ConnectionEvent};
use nautilus_core::event_bus::EventBus;

pub struct Submarine {
    pub connections: Arc<RwLock<HashMap<String, Arc<Mutex<TcpConnection>>>>>,
    transport: Arc<TcpTransport>,
    event_bus: Arc<EventBus<ConnectionEvent>>,
    event_tx: mpsc::UnboundedSender<SubmarineEvent>,
    event_rx: Option<mpsc::UnboundedReceiver<SubmarineEvent>>,
}

#[derive(Debug)]
pub enum SubmarineEvent {
    ConnectionEstablished(String),
    ConnectionClosed(String),
    DataReceived(String, Vec<u8>),
}

impl Submarine {
    /// Create a new `Submarine` instance
    pub async fn new() -> Self {
        let conn_event_bus = Arc::new(EventBus::<ConnectionEvent>::new(100));
        let tcp_event_bus = Arc::new(EventBus::<TcpEvent>::new(100));
        let transport = Arc::new(TcpTransport::new(
            Arc::clone(&conn_event_bus),
            Arc::clone(&tcp_event_bus),
        ));

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            transport,
            event_bus: conn_event_bus,
            event_tx,
            event_rx: Some(event_rx),
        }
    }

    /// Start the `Submarine` event loop
    pub async fn start(&mut self) {
        let mut event_rx = self.event_rx.take().expect("event_rx already taken");
        let connections = Arc::clone(&self.connections);

        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                match event {
                    SubmarineEvent::ConnectionEstablished(peer_id) => {
                        println!("Connection established with peer: {}", peer_id);
                    }
                    SubmarineEvent::ConnectionClosed(peer_id) => {
                        println!("Connection closed with peer: {}", peer_id);
                        connections.write().await.remove(&peer_id);
                    }
                    SubmarineEvent::DataReceived(peer_id, data) => {
                        println!("Data received from {}: {:?}", peer_id, data);
                    }
                }
            }
        });
    }

    /// Connect to a peer
    pub async fn connect(&self, peer_id: String, addr: &str) -> Result<(), String> {
        let connection = self
            .transport
            .dial(addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", addr, e))?;
        let connection_arc = Arc::new(Mutex::new(connection));

        let connections = Arc::clone(&self.connections);
        let event_tx = self.event_tx.clone();
        let peer_id_task = peer_id.clone();
        let connection_clone = Arc::clone(&connection_arc);

        tokio::spawn(async move {
            while let Ok(data) = connection_clone.lock().await.receive().await {
                if event_tx
                    .send(SubmarineEvent::DataReceived(peer_id_task.clone(), data))
                    .is_err()
                {
                    eprintln!("Failed to send DataReceived event for {}", peer_id_task);
                }
            }

            if event_tx
                .send(SubmarineEvent::ConnectionClosed(peer_id_task))
                .is_err()
            {
                eprintln!("Failed to send ConnectionClosed event");
            }
        });

        self.connections
            .write()
            .await
            .insert(peer_id.clone(), connection_arc);

        if self
            .event_tx
            .send(SubmarineEvent::ConnectionEstablished(peer_id))
            .is_err()
        {
            eprintln!("Failed to send ConnectionEstablished event");
        }

        Ok(())
    }

    /// Send a message to a specific peer
    pub async fn send_message(&self, peer_id: &str, message: Vec<u8>) -> Result<(), String> {
        let connections = self.connections.read().await;
        if let Some(conn) = connections.get(peer_id) {
            conn.lock().await.send(&message).await.map_err(|e| e.to_string())
        } else {
            Err(format!("No active connection for peer {}", peer_id))
        }
    }

    /// Disconnect from a specific peer
    pub async fn disconnect(&self, peer_id: &str) -> Result<(), String> {
        let mut connections = self.connections.write().await;
        if let Some(mut conn) = connections.remove(peer_id) {
            conn.lock().await.disconnect().await.map_err(|e| e.to_string())
        } else {
            Err(format!("No active connection for peer {}", peer_id))
        }
    }

    /// Broadcast a message to all connected peers
    pub async fn broadcast_message(&self, message: Vec<u8>) {
        let connections = self.connections.read().await;
        for (peer_id, conn) in connections.iter() {
            if let Err(e) = conn.lock().await.send(&message).await {
                eprintln!("Failed to send message to {}: {}", peer_id, e);
            } else {
                println!("Message sent to {}", peer_id);
            }
        }
    }

    /// Get the event receiver for testing or external usage
    pub fn take_event_receiver(&mut self) -> Option<mpsc::UnboundedReceiver<SubmarineEvent>> {
        self.event_rx.take()
    }
}
