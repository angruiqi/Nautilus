# Nautilus mDNS Protocol

The `nautilus_mdns` module implements a robust Multicast DNS (mDNS)-based Node Discovery Protocol for decentralized networks. This protocol enables service and node discovery, registration, and management in local networks using mDNS.

---

## Features

### 1. **Service Discovery**
- Discovers services in the local network using mDNS queries.
- Periodic announcements of local services to notify peers.

### 2. **Node Discovery**
- Identifies and registers nodes in the local network.
- Updates node information dynamically based on mDNS responses.

### 3. **Registry Management**
- Maintains a registry for services and nodes.
- Enforces TTL (Time-To-Live) expiration for stale records.
- Capacity-limited registry to optimize memory usage.

### 4. **Event-Driven Design**
- Emits structured events for higher-level modules to react to mDNS activities.
  - `Discovered` (new records)
  - `Updated` (refreshed TTL)
  - `Expired` (records removed from the registry)

### 5. **Error Handling**
- Handles packet serialization/deserialization issues.
- Manages network-related errors, including multicast setup failures.

---

## Architecture

The protocol consists of the following core components:

### **1. Packet Handling**
- **`DnsPacket`**: Represents mDNS packets with serialization and parsing functionality.
- **`DnsRecord`**: Supports multiple DNS record types (A, PTR, SRV, TXT).
- **`DnsName`**: Handles domain name parsing and formatting.

### **2. mDNS Service**
- **`MdnsService`**:
  - Sets up multicast UDP sockets for mDNS communication.
  - Sends periodic queries and advertisements.
  - Processes incoming mDNS packets.

### **3. Registry Management**
- **`MdnsRegistry`**:
  - Maintains service and node records.
  - Handles TTL expiration and capacity enforcement.

### **4. Events and Errors**
- **`MdnsEvent`**: Defines structured events emitted by the protocol.
- **`MdnsError`**: Captures and categorizes errors within the protocol.

---

## Installation

To use `nautilus_mdns` in your Rust project:

1. Add the dependency to your `Cargo.toml`:
   ```toml
   [dependencies]
   socket2 = "0.4"
   tokio = { version = "1", features = ["full"] }
   serde = { version = "1", features = ["derive"] }
   bytes = "1.0"
   ```

2. Clone or import the `nautilus_mdns` module into your project.

---

## Usage

### Setting Up the mDNS Service
```rust
use nautilus_mdns::MdnsService;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let mdns_service = MdnsService::new().await.expect("Failed to initialize mDNS service");
    let mdns_service = Arc::new(mdns_service);

    // Run the mDNS service with periodic queries and advertisements
    mdns_service.run("_http._tcp.local.".to_string(), 10, 30).await;
}
```

### Registering a Local Service
```rust
let mdns_service = MdnsService::new().await.expect("Failed to initialize mDNS service");

mdns_service
    .register_local_service(
        "my-service.local".to_string(),
        "_http._tcp.local".to_string(),
        8080,
        Some(120),
        "my-node.local".to_string(),
    )
    .await
    .expect("Failed to register local service");
```

### Listening for Packets
```rust
mdns_service
    .listen()
    .await
    .expect("Failed to start mDNS listener");
```

### Processing Events
React to discovery events emitted by the protocol:
```rust
match event {
    MdnsEvent::Discovered(record) => println!("Discovered: {:?}", record),
    MdnsEvent::Updated(record) => println!("Updated: {:?}", record),
    MdnsEvent::Expired(record) => println!("Expired: {:?}", record),
    _ => {}
}
```

---

## Testing

### Basic Test
- Verify that nodes can discover each other using mDNS queries and responses.
```rust
#[tokio::test]
async fn test_node_discovery() {
    let mdns_service = MdnsService::new().await.unwrap();
    mdns_service.register_local_service(
        "test-service.local".to_string(),
        "_http._tcp.local".to_string(),
        8080,
        Some(120),
        "test-node.local".to_string(),
    ).await.unwrap();

    let nodes = mdns_service.registry.list_nodes().await;
    assert!(!nodes.is_empty());
}
```

### Stress Test
- Test with a high number of services and nodes.
```rust
#[tokio::test]
async fn stress_test_service_registry() {
    let mdns_service = MdnsService::new().await.unwrap();
    for i in 0..100 {
        mdns_service.register_local_service(
            format!("service-{}.local", i),
            "_http._tcp.local".to_string(),
            8000 + i as u16,
            Some(60),
            format!("node-{}.local", i),
        ).await.unwrap();
    }

    let services = mdns_service.registry.list_services().await;
    assert_eq!(services.len(), 50); // Capacity limit enforced
}
```

### Integration Test
- Simulate end-to-end discovery between multiple nodes.
```rust
#[tokio::test]
async fn integration_test_mdns_discovery() {
    let service1 = MdnsService::new().await.unwrap();
    let service2 = MdnsService::new().await.unwrap();

    service1.register_local_service(
        "service1.local".to_string(),
        "_http._tcp.local".to_string(),
        8081,
        Some(120),
        "node1.local".to_string(),
    ).await.unwrap();

    service2.register_local_service(
        "service2.local".to_string(),
        "_http._tcp.local".to_string(),
        8082,
        Some(120),
        "node2.local".to_string(),
    ).await.unwrap();

    // Simulate a query from service1 for _http._tcp.local
    service1.periodic_query("_http._tcp.local", 5).await;

    let nodes = service1.registry.list_nodes().await;
    assert!(!nodes.is_empty());
}
```

---

## Limitations
1. **Local Network Only**: The protocol is limited to local subnets due to the nature of mDNS.
2. **No Authentication**: Nodes/services are added to the registry without verification.
3. **Multicast Overhead**: mDNS traffic increases with the number of nodes in the network.

---

## Future Improvements
- Add support for authentication and encryption.
- Extend discovery across subnets using relays or proxies.
- Implement a Gossip Protocol for registry synchronization in larger networks.
- Integrate metrics collection and monitoring.

---

## License
This project is licensed under the MIT License. See the LICENSE file for details.

---

## Contributions
Contributions are welcome! Please create an issue or submit a pull request with your improvements or bug fixes.

---