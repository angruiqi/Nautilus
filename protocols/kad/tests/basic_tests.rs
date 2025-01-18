// protocols\kad\tests\basic_tests.rs
use kad::node::{Node, NodeId};
use kad::xor_distance::{xor_distance, is_closer};
use kad::routing_table::RoutingTable;
use kad::kad_protocol::KadProtocol;
use kad::utils::generate_random_node_id;
use kad::kad_message::{KadMessage, MessageType};
use udp::UdpConnection;
use std::net::{SocketAddr, TcpListener};
use nautilus_core::connection::Datagram;


/// Utility function to get an unused local port
fn get_unused_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn mock_remote_node(address: &str) -> tokio::task::JoinHandle<()> {
    let address = address.to_owned();
    tokio::spawn(async move {
        let conn = UdpConnection::new();
        conn.bind(&address).await.expect("Failed to bind mock node");

        loop {
            let (message, sender) = conn.receive_from().await.expect("Failed to receive message");
            let kad_message = KadMessage::deserialize(&message).expect("Failed to deserialize");

            match kad_message.message_type {
                MessageType::Ping => {
                    let response = KadMessage::new(MessageType::Pong, kad_message.sender_id, None);
                    conn.send_to(&response.serialize(), &sender.to_string())
                        .await
                        .expect("Failed to send Pong");
                }
                MessageType::FindNode => {
                    let response = KadMessage::new(MessageType::NodeFound, kad_message.sender_id, None);
                    conn.send_to(&response.serialize(), &sender.to_string())
                        .await
                        .expect("Failed to send NodeFound");
                }
                _ => {}
            }
        }
    })
}

#[test]
fn test_node_creation() {
    let id: NodeId = [1u8; 20];
    let address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let node = Node::new(id, address);

    assert_eq!(node.id, id);
    assert_eq!(node.address, address);
}

#[test]
fn test_xor_distance() {
    let id1: NodeId = [0u8; 20];
    let id2: NodeId = [255u8; 20];
    let distance = xor_distance(&id1, &id2);

    assert_eq!(distance, [255u8; 20]); // XOR of 0 and 255 is 255
}

#[test]
fn test_is_closer() {
    let id1: NodeId = [50u8; 20];
    let id2: NodeId = [200u8; 20];
    let target: NodeId = [100u8; 20];

    let dist1 = xor_distance(&id1, &target);
    let dist2 = xor_distance(&id2, &target);

    assert!(is_closer(&dist1, &dist2, &target));
}

#[test]
fn test_routing_table_add_and_find_closest_nodes() {
    let local_id: NodeId = [0u8; 20];
    let local_address: SocketAddr = "127.0.0.1:8080".parse().unwrap();
    let local_node = Node::new(local_id, local_address);

    let mut routing_table = RoutingTable::new(local_node);

    // Add nodes
    let id1: NodeId = [1u8; 20];
    let id2: NodeId = [2u8; 20];
    let node1 = Node::new(id1, "192.168.1.1:8080".parse().unwrap());
    let node2 = Node::new(id2, "192.168.1.2:8080".parse().unwrap());
    routing_table.add_node(node1.clone());
    routing_table.add_node(node2.clone());

    // Find closest nodes
    let target_id: NodeId = [1u8; 20];
    let closest_nodes = routing_table.find_closest_nodes(&target_id, 2);

    assert_eq!(closest_nodes.len(), 2);
    assert!(closest_nodes.contains(&node1));
    assert!(closest_nodes.contains(&node2));
}

#[tokio::test]
async fn test_kad_protocol_ping() {
    let local_id = generate_random_node_id();
    let local_address: SocketAddr = format!("127.0.0.1:{}", get_unused_port()).parse().unwrap();
    let local_node = Node::new(local_id, local_address);

    let remote_id = generate_random_node_id();
    let remote_address: SocketAddr = format!("127.0.0.1:{}", get_unused_port()).parse().unwrap();
    let remote_node = Node::new(remote_id, remote_address);

    let kad = KadProtocol::new(local_node.clone()).await;
    {
        let kad_instance = kad.lock().await;
        let _ = kad_instance.bind(&local_node.address.to_string()).await;
    }

    // Mock the remote node
    let mock = mock_remote_node(&remote_node.address.to_string()).await;

    {
        let kad_instance = kad.lock().await;
        let is_alive = kad_instance.ping(&remote_node).await;
        assert!(is_alive); // Should return true as the mock node responds
    }

    mock.abort(); // Clean up the mock node
}
