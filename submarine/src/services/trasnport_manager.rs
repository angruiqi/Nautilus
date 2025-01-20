// submarine\src\services\trasnport_manager.rs
use tcp::TcpTransport;
use udp::UdpConnection;
use nautilus_core::connection::{Connection,Datagram,Transport,TransportListener};
use std::sync::Arc;

pub struct TransportManager {
  pub tcp_transport: Arc<TcpTransport>,
  pub udp_transport: Arc<UdpConnection>,
}

impl TransportManager {
  pub fn new(tcp: Arc<TcpTransport>, udp: Arc<UdpConnection>) -> Self {
      Self {
          tcp_transport: tcp,
          udp_transport: udp,
      }
  }

  pub async fn send(&self, address: &str, data: &[u8], secure: bool) -> Result<(), String> {
      if secure {
          let mut connection = self.tcp_transport.dial(address).await.map_err(|e| e.to_string())?;
          connection.send(data).await.map_err(|e| e.to_string())?;
      } else {
          self.udp_transport.send_to(data, address).await.map_err(|e| e.to_string())?;
      }
      Ok(())
  }

  pub async fn receive(&self, secure: bool) -> Result<Vec<u8>, String> {
      if secure {
          let mut listener = self.tcp_transport.listen("0.0.0.0:8080").await.map_err(|e| e.to_string())?;
          let mut connection = listener.accept().await.map_err(|e| e.to_string())?;
          connection.receive().await.map_err(|e| e.to_string())
      } else {
          let (data, _) = self.udp_transport.receive_from().await.map_err(|e| e.to_string())?;
          Ok(data)
      }
  }
}
