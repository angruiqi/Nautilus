use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::sync::Arc;

use tls::TlsConnection;
use tls::TlsState;
// Reuse your handshake crate to build a Handshake
use handshake::{Handshake, HandshakeStep};

use nautilus_core::connection::Connection;

// If you want to re-use "HelloStep" from your local `tls::handshake` module:
use tls::{HelloStep, HandshakeRole};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Run server and client concurrently
    tokio::try_join!(run_server(), run_client())?;
    Ok(())
}

async fn run_server() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:8080").await?;
    println!("[Server] Listening on 127.0.0.1:8080");

    if let Ok((socket, addr)) = listener.accept().await {
        println!("[Server] Accepted connection from {}", addr);

        let mut handshake = Handshake::new("TLS_HANDSHAKE");
        let hello_step = HelloStep::new("TLS_HANDSHAKE", HandshakeRole::Responder);
        handshake.add_step(Box::new(hello_step));

        let mut connection = TlsConnection::new(socket, handshake).await?;
        println!("[Server] Secure connection established");

        // Send encrypted data
        connection.send(b"Hello, client!").await?;
        println!("[Server] Encrypted message sent");
    }

    Ok(())
}

async fn run_client() -> Result<(), Box<dyn std::error::Error>> {
    // Sleep to give server time to bind & accept
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    let socket = TcpStream::connect("127.0.0.1:8080").await?;
    println!("[Client] Connected to server");

    let mut handshake = Handshake::new("TLS_HANDSHAKE");
    let hello_step = HelloStep::new("TLS_HANDSHAKE", HandshakeRole::Initiator);
    handshake.add_step(Box::new(hello_step));

    let mut connection = TlsConnection::new(socket, handshake).await?;
    println!("[Client] Secure connection established");

    // Receive encrypted data
    let message = connection.receive().await?;
    println!("[Client] Received encrypted message: {:?}", String::from_utf8(message)?);

    Ok(())
}
