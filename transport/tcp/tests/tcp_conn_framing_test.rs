
#[cfg(test)]
mod tests {
    #[cfg(feature = "framing")]
    use super::*;
    #[cfg(feature = "framing")]
    use tokio::net::TcpListener;
    #[cfg(feature = "framing")]
    use std::sync::Arc;
    #[cfg(feature = "framing")]
    use nautilus_core::event_bus::EventBus;
    #[cfg(feature = "framing")]
    use nautilus_core::connection::{ConnectionEvent, Connection};
    #[cfg(feature = "framing")]
    use tcp::{TcpConnection, TcpEvent};
    #[cfg(feature = "framing")]
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    #[cfg(feature = "framing")]
    async fn test_send_and_receive_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Simulate sending a framed message
            let message = b"Hello, framed world!";
            let length = (message.len() as u32).to_be_bytes();
            socket.write_all(&length).await.unwrap();
            socket.write_all(message).await.unwrap();
        });

        let conn_event_bus = Arc::new(EventBus::<ConnectionEvent>::new(100));
        let tcp_event_bus = Arc::new(EventBus::<TcpEvent>::new(100));
        let mut conn = TcpConnection::new(conn_event_bus, tcp_event_bus);

        conn.connect(&local_addr.to_string()).await.unwrap();

        // Receive the framed message
        let response = conn.receive_frame().await.unwrap();
        assert_eq!(response, b"Hello, framed world!");
    }

    #[tokio::test]
    #[cfg(feature = "framing")]
    async fn test_partial_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Send a partial frame (only the length header)
            let length = (10 as u32).to_be_bytes();
            socket.write_all(&length).await.unwrap();
        });

        let conn_event_bus = Arc::new(EventBus::<ConnectionEvent>::new(100));
        let tcp_event_bus = Arc::new(EventBus::<TcpEvent>::new(100));
        let mut conn = TcpConnection::new(conn_event_bus, tcp_event_bus);

        conn.connect(&local_addr.to_string()).await.unwrap();

        // Attempt to receive the incomplete frame
        let result = conn.receive_frame().await;
        assert!(result.is_err(), "Expected error for partial frame, got {:?}", result);
    }

    #[tokio::test]
    #[cfg(feature = "framing")]
    async fn test_invalid_frame_header() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Send an invalid frame header (random data instead of length)
            socket.write_all(&[0xFF, 0xFF, 0xFF, 0xFF]).await.unwrap();
        });

        let conn_event_bus = Arc::new(EventBus::<ConnectionEvent>::new(100));
        let tcp_event_bus = Arc::new(EventBus::<TcpEvent>::new(100));
        let mut conn = TcpConnection::new(conn_event_bus, tcp_event_bus);

        conn.connect(&local_addr.to_string()).await.unwrap();

        // Attempt to receive the invalid frame
        let result = conn.receive_frame().await;
        assert!(result.is_err(), "Expected error for invalid frame header, got {:?}", result);
    }

    #[tokio::test]
    #[cfg(feature = "framing")]
    async fn test_connection_closure_during_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Send part of the frame and then close the connection
            let length = (10 as u32).to_be_bytes();
            socket.write_all(&length).await.unwrap();
            socket.shutdown().await.unwrap(); // Close connection prematurely
        });

        let conn_event_bus = Arc::new(EventBus::<ConnectionEvent>::new(100));
        let tcp_event_bus = Arc::new(EventBus::<TcpEvent>::new(100));
        let mut conn = TcpConnection::new(conn_event_bus, tcp_event_bus);

        conn.connect(&local_addr.to_string()).await.unwrap();

        // Attempt to receive the frame from a closed connection
        let result = conn.receive_frame().await;
        assert!(result.is_err(), "Expected error for connection closure, got {:?}", result);
    }

    #[tokio::test]
    #[cfg(feature = "framing")]
    async fn test_large_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();

            // Send a large frame (e.g., 1 MB)
            let data = vec![0x41; 1 * 1024 * 1024]; // 1 MB of 'A's
            let length = (data.len() as u32).to_be_bytes();
            socket.write_all(&length).await.unwrap();
            socket.write_all(&data).await.unwrap();
        });

        let conn_event_bus = Arc::new(EventBus::<ConnectionEvent>::new(100));
        let tcp_event_bus = Arc::new(EventBus::<TcpEvent>::new(100));
        let mut conn = TcpConnection::new(conn_event_bus, tcp_event_bus);

        conn.connect(&local_addr.to_string()).await.unwrap();

        // Receive the large frame
        let response = conn.receive_frame().await.unwrap();
        assert_eq!(response.len(), 1 * 1024 * 1024, "Expected 1 MB frame");
        assert_eq!(response, vec![0x41; 1 * 1024 * 1024]);
    }
}