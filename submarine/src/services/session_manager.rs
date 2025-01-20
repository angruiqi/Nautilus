// submarine\src\services\session_manager.rs
use std::collections::HashMap;
use tokio::sync::Mutex;
use std::sync::Arc;
use tls::{TlsSession,HandshakeRole};
use tokio::net::TcpStream;
pub struct SessionManager {
    sessions: Arc<Mutex<HashMap<String, TlsSession>>>,
}

impl SessionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub async fn add_session(&self, addr: String, connection: TlsSession) {
        let mut sessions = self.sessions.lock().await;
        sessions.insert(addr, connection);
    }

    pub async fn remove_session(&self, addr: &str) {
        let mut sessions = self.sessions.lock().await;
        sessions.remove(addr);
    }

    pub async fn send(&self, addr: &str, data: &[u8]) -> Result<(), String> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(addr) {
            session.send(data).await.map_err(|e| e.to_string())?;
            Ok(())
        } else {
            Err("Session not found".to_string())
        }
    }

    pub async fn receive(&self, addr: &str) -> Result<Vec<u8>, String> {
        let mut sessions = self.sessions.lock().await;
        if let Some(session) = sessions.get_mut(addr) {
            session.receive().await.map_err(|e| e.to_string())
        } else {
            Err("Session not found".to_string())
        }
    }
    pub async fn initiate_session(&self, addr: &str) -> Result<TlsSession, String> {
      let socket = TcpStream::connect(addr)
          .await
          .map_err(|e| format!("Failed to connect: {}", e))?;

      let session = TlsSession::new(socket, HandshakeRole::Initiator)
          .await
          .map_err(|e| format!("TLS handshake failed: {}", e))?;

      Ok(session)
  }
}
