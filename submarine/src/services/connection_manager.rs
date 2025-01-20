use std::sync::Arc;
use tokio::sync::Mutex;
use log::info;

use kad::kad_protocol::KadProtocol;
use kad::node::NodeId;
use crate::services::trasnport_manager::TransportManager;
use crate::services::session_manager::SessionManager;

use nautilus_core::connection::{Transport,TransportListener};
use tcp::Connection;
/// ConnectionManager coordinates:
/// - Listening on ports for inbound connections (TCP/UDP, possibly TLS)
/// - Dialing outbound connections
/// - (Optionally) looking up addresses via Kad or checking the routing table
/// - Creating and storing TLS sessions if `secure == true`
pub struct ConnectionManager {
    kad: Arc<Mutex<KadProtocol>>,
    transport_mgr: Arc<TransportManager>,
    session_mgr: Arc<SessionManager>,
}

impl ConnectionManager {
    /// Build a new ConnectionManager
    pub fn new(
        kad: Arc<Mutex<KadProtocol>>,
        transport_mgr: Arc<TransportManager>,
        session_mgr: Arc<SessionManager>,
    ) -> Self {
        Self { kad, transport_mgr, session_mgr }
    }

    // =============== Outbound Dial ===============

    /// Dial a remote peer's address. Optionally secure with TLS.
    ///
    /// If `secure = true`, we create a TLS session (and store it in SessionManager).
    /// If `secure = false`, we just do a plain TCP dial or a one-shot UDP send, 
    /// depending on your preference.
    pub async fn dial(
        &self,
        address: &str,
        secure: bool,
        data: Option<&[u8]>,
    ) -> Result<(), String> {
        if secure {
            // *** TLS approach with SessionManager ***
            let session = self.session_mgr.initiate_session(address).await?;
            // store it for future sends
            self.session_mgr.add_session(address.to_string(), session).await;

            // If you want to send data right away:
            if let Some(d) = data {
                self.session_mgr.send(address, d).await?;
            }
        } else {
            // *** Non-secure approach ***
            // Either do a one-shot UDP or a plain TCP connect
            // Example: plain TCP connect & send:

            // 1) dial TCP
            let res_conn = self.transport_mgr.tcp_transport.dial(address)
                .await.map_err(|e| e.to_string())?;
            let mut conn = res_conn;

            // 2) if there's data, send it
            if let Some(d) = data {
                conn.send(d).await.map_err(|e| e.to_string())?;
            }

            // Optionally keep `conn` around in a manager if you want 
            // a persistent connection. If not, drop it for ephemeral.
        }
        Ok(())
    }

    // =============== Inbound Listen ===============

    /// Start listening on a local address (e.g. "0.0.0.0:9000") for inbound TCP.
    /// If `secure = true`, do a TLS handshake; else plain TCP.
    /// Meanwhile, for UDP, you might already be bound in `UdpConnection`.
    pub async fn listen(
        &self,
        local_addr: &str,
        secure: bool,
    ) -> Result<(), String> {
        if secure {
            // Example: If you want to handle incoming TLS by a “passive” approach:
            // 1) Bind a standard TCP listener
            // 2) Accept a connection
            // 3) Start a TlsSession as the Responder
            // and store it in session_mgr
            //
            // The SessionManager might have a method like:
            // session_mgr.accept_and_handshake(local_addr) -> TlsSession
            // (not implemented in your code yet, but you can adapt).
            return Err("Secure listen not implemented. Provide a method in SessionManager if you want inbound TLS".into());
        } else {
            // *** Non-secure approach: plain TCP listening. ***
            let mut listener = self.transport_mgr
                .tcp_transport.listen(local_addr)
                .await.map_err(|e| e.to_string())?;

            // For a simple approach, spawn a task that repeatedly accepts:
            tokio::spawn(async move {
                loop {
                    match listener.accept().await {
                        Ok(mut conn) => {
                            // handle inbound connection
                            info!("(ConnectionManager) Inbound TCP accepted from ???");
                            // e.g. read once:
                            if let Ok(data) = conn.receive().await {
                                info!("(ConnectionManager) Received inbound: {:?}", data);
                            }
                            // optionally respond or keep `conn` in a manager
                        }
                        Err(err) => {
                            info!("(ConnectionManager) Failed to accept: {:?}", err);
                            break;
                        }
                    }
                }
            });
        }

        Ok(())
    }

    // =============== Kad Integration ===============

    /// Attempt to open a connection to a peer by NodeId. If the routing table
    /// knows the Node's address, we dial it. If not, we can do an iterative find.
    pub async fn dial_by_node_id(
        &self,
        peer_id: NodeId,
        secure: bool,
    ) -> Result<(), String> {
        // 1) find peer address from Kad
        let address = self.find_peer_address(peer_id).await?;
        // 2) dial 
        self.dial(&address, secure, None).await?;
        Ok(())
    }

    async fn find_peer_address(&self, peer_id: NodeId) -> Result<String, String> {
        // check if peer in routing table
        let kad_guard = self.kad.lock().await;
        let all_nodes = kad_guard.routing_table.lock().await.get_all_nodes();
        if let Some(n) = all_nodes.iter().find(|x| x.id == peer_id) {
            return Ok(n.address.to_string());
        }
        drop(kad_guard);

        // run iterative_find_node to see if we can discover it
        let discovered = self.kad.lock().await
            .iterative_find_node(peer_id.clone()).await;
        if discovered.is_empty() {
            return Err(format!("(ConnectionManager) Could not find NodeId={}", hex::encode(peer_id)));
        }
        // check again
        let kad_guard2 = self.kad.lock().await;
        let all_nodes2 = kad_guard2.routing_table.lock().await.get_all_nodes();
        if let Some(n) = all_nodes2.iter().find(|x| x.id == peer_id) {
            Ok(n.address.to_string())
        } else {
            Err(format!("(ConnectionManager) After find_node, still no NodeId={}", hex::encode(peer_id)))
        }
    }
}
