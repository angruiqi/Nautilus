use std::net::UdpSocket;
use std::time::Duration;

/// Represents a peer in the decentralized network
pub struct Peer {
    pub addr: String,
}

impl Peer {
    /// Starts a peer to listen for `PING` messages and respond with `ALIVE`
    pub fn start_listener(&self) -> Result<(), String> {
        let socket = UdpSocket::bind(&self.addr).map_err(|e| format!("Failed to bind socket: {}", e))?;
        println!("Peer listening on {}", self.addr);

        let mut buffer = [0u8; 1024];
        loop {
            // Receive messages
            match socket.recv_from(&mut buffer) {
                Ok((size, src)) => {
                    let received = String::from_utf8_lossy(&buffer[..size]);
                    if received == "PING" {
                        println!("Received PING from {}", src);
                        // Respond with ALIVE
                        socket
                            .send_to(b"ALIVE", src)
                            .map_err(|e| format!("Failed to send response: {}", e))
                            .ok();
                    }
                }
                Err(err) => {
                    println!("Error receiving data: {}", err);
                }
            }
        }
    }

    /// Sends a `PING` to the target address and waits for an `ALIVE` response
    pub fn send_ping(&self, target: &str, timeout_secs: u64) -> Result<bool, String> {
        let socket = UdpSocket::bind("0.0.0.0:0").map_err(|e| format!("Failed to bind socket: {}", e))?;
        socket
            .set_read_timeout(Some(Duration::from_secs(timeout_secs)))
            .map_err(|e| format!("Failed to set timeout: {}", e))?;

        // Send PING
        socket
            .send_to(b"PING", target)
            .map_err(|e| format!("Failed to send PING: {}", e))?;
        println!("Sent PING to {}", target);

        // Wait for ALIVE
        let mut buffer = [0u8; 1024];
        match socket.recv_from(&mut buffer) {
            Ok((size, _src)) => {
                let response = String::from_utf8_lossy(&buffer[..size]);
                if response == "ALIVE" {
                    println!("Received ALIVE response");
                    return Ok(true);
                }
                Ok(false)
            }
            Err(_) => Ok(false), // Timeout or other error
        }
    }
}