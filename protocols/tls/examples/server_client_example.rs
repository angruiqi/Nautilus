use tokio::net::{TcpListener, TcpStream};
// We only need these if we do direct reading/writing here, but let's remove if not used:
// use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::{Arc, Mutex};

use tls::{TlsConnection, TlsState, HelloStep, HandshakeRole, KyberExchangeStep,FinishStep};
use handshake::Handshake;

// If you’re using `nautilus_core::connection::Connection`:
use nautilus_core::connection::Connection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio::try_join!(run_server(), run_client())?;
    Ok(())
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("[Server] Listening on 127.0.0.1:8080");

    if let Ok((socket, addr)) = listener.accept().await {
        println!("[Server] Accepted connection from {}", addr);

        // 1) Shared TlsState (Arc<Mutex<>> so Kyber can lock & store final key)
        let state = Arc::new(Mutex::new(TlsState::default()));

        // 2) Build handshake with HelloStep + KyberExchangeStep
        let mut handshake = Handshake::new("TLS_HANDSHAKE"); // Both steps must match "TLS_HANDSHAKE"

        // Hello step as Responder
        let hello_step = HelloStep::new("TLS_HANDSHAKE", HandshakeRole::Responder);
        // Kyber step as Responder
        let kyber_step = KyberExchangeStep::new(HandshakeRole::Responder, state.clone());

        handshake.add_step(Box::new(hello_step));
        handshake.add_step(Box::new(kyber_step));
        handshake.add_step(Box::new(FinishStep { role: HandshakeRole::Responder }));
        // 3) Create TlsConnection -> handshake is executed inside .new()
        let mut connection = TlsConnection::new(socket, handshake, state).await?;
        println!("[Server] Secure connection established");

        // 4) Send an encrypted message
        connection.send(b"Hello, client!").await?;
        println!("[Server] Encrypted message sent");
    }
    Ok(())
}

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let socket = TcpStream::connect("127.0.0.1:8080").await?;
    println!("[Client] Connected to server");

    // 1) Shared TlsState
    let state = Arc::new(Mutex::new(TlsState::default()));

    // 2) Build handshake (Initiator side)
    let mut handshake = Handshake::new("TLS_HANDSHAKE"); 

    let hello_step = HelloStep::new("TLS_HANDSHAKE", HandshakeRole::Initiator);
    let kyber_step = KyberExchangeStep::new(HandshakeRole::Initiator, state.clone());

    handshake.add_step(Box::new(hello_step));
    handshake.add_step(Box::new(kyber_step));
    handshake.add_step(Box::new(FinishStep { role: HandshakeRole::Initiator }));
    // 3) TlsConnection -> runs the handshake
    let mut connection = TlsConnection::new(socket, handshake, state).await?;
    println!("[Client] Secure connection established");

    // 4) Receive encrypted message
    let message = connection.receive().await?;
    println!("[Client] Received encrypted message: {}", 
        String::from_utf8_lossy(&message)
    );
    Ok(())
}
