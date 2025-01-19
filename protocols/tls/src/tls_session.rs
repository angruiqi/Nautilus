use tokio::net::{TcpStream,TcpListener};
use std::sync::{Arc, Mutex};
use crate::{TlsConnection, TlsState, HelloStep, HandshakeRole, KyberExchangeStep, FinishStep};
use handshake::Handshake;
use nautilus_core::connection::Connection;
use std::time::Duration;
use tokio::time::timeout;

pub struct TlsSession {
    connection: TlsConnection,
}

impl TlsSession {
  pub async fn new(
    socket: TcpStream, 
    role: HandshakeRole
) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
    let state = Arc::new(Mutex::new(TlsState::default()));

    let mut handshake = Handshake::new("TLS_HANDSHAKE");

    let hello_step = HelloStep::new("TLS_HANDSHAKE", role);
    let kyber_step = KyberExchangeStep::new(role, state.clone());

    handshake.add_step(Box::new(hello_step));
    handshake.add_step(Box::new(kyber_step));
    handshake.add_step(Box::new(FinishStep { role }));

    let connection = TlsConnection::new(socket, handshake, state)
    .await
    .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?;

    println!("[Session] Secure connection established for {:?}", role);

    Ok(Self { connection })
}

pub async fn send(&mut self, message: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    self.connection.send(message).await?;
    Ok(())
}

pub async fn receive(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let message = self.connection.receive().await?;
    Ok(message)
}
}



pub struct AdaptiveTlsSession {
  connection: TlsConnection,
}

impl AdaptiveTlsSession {
  /// Create a new Adaptive TLS Session
  pub async fn new(address: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
      let state = Arc::new(Mutex::new(TlsState::default()));

      let listener = TcpListener::bind(address).await?;
      
      println!("[Adaptive Session] Listening for incoming connection on {}", address);

      let accept_future = listener.accept();
      
      // Set a timeout to determine if the session should initiate or accept
      match timeout(Duration::from_secs(2), accept_future).await {
        Ok(Ok((socket, _))) => {
            println!("[Adaptive Session] Acting as Responder");
            Self::setup_session(socket, HandshakeRole::Responder, state).await
        }
        Ok(Err(e)) => {
            println!("[Adaptive Session] Listener error: {}", e);
            Err(Box::new(e))
        }
        Err(_) => {
            println!("[Adaptive Session] Acting as Initiator");
            let socket = TcpStream::connect(address).await?;
            Self::setup_session(socket, HandshakeRole::Initiator, state).await
        }
    }
  }

  /// Setup the TLS session based on role
  async fn setup_session(
      socket: TcpStream,
      role: HandshakeRole,
      state: Arc<Mutex<TlsState>>,
  ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
      let mut handshake = Handshake::new("TLS_HANDSHAKE");

      let hello_step = HelloStep::new("TLS_HANDSHAKE", role);
      let kyber_step = KyberExchangeStep::new(role, state.clone());

      handshake.add_step(Box::new(hello_step));
      handshake.add_step(Box::new(kyber_step));
      handshake.add_step(Box::new(FinishStep { role }));

      let connection = TlsConnection::new(socket, handshake, state)
          .await
          .map_err(|e| Box::<dyn std::error::Error + Send + Sync>::from(e))?;

      println!("[Adaptive Session] Secure connection established as {:?}", role);

      Ok(Self { connection })
  }

  /// Send data over the TLS session
  pub async fn send(&mut self, message: &[u8]) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
      self.connection.send(message).await?;
      Ok(())
  }

  /// Receive data over the TLS session
  pub async fn receive(&mut self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
      let message = self.connection.receive().await?;
      Ok(message)
  }
}