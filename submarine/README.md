# Submarine Project

Submarine is a decentralized networking solution that integrates mDNS (Multicast DNS) and Kad (Kademlia DHT) to enable service discovery and distributed hash table operations across a network.

## Features
- **Automatic Service Discovery** using mDNS.
- **Distributed Hash Table (DHT)** for decentralized storage and lookup.
- **Microservice-Friendly Architecture** with structured service management.
- **Periodic Queries and Advertisements** to keep the network updated.
- **Graceful Shutdown Handling** ensuring clean resource release.

## Project Structure
```
submarine/
│-- src/
│   ├── services/
│   │   ├── service_manager.rs   # Core service orchestration
│   │   ├── discovery.rs         # Handles mDNS discovery
│   │   ├── kad_service.rs       # Handles Kad DHT operations
│   ├── main.rs                  # Application entry point
│-- Cargo.toml                    # Rust dependencies
│-- README.md                     # Project documentation
```

## Getting Started

### Prerequisites
Ensure you have the following installed:
- **Rust** (latest stable version)
- **Tokio** (for async runtime)
- **mdns** crate (for service discovery)
- **kad** crate (for DHT operations)

### Installation
Clone the repository and navigate to the project directory:
```bash
git clone https://github.com/yourrepo/submarine.git
cd submarine
```

### Running the Project

1. Build the project:
   ```bash
   cargo build --release
   ```

2. Run the project:
   ```bash
   cargo run --release
   ```

### Example Usage

```rust
let device_origin = "my-submarine-device.local";
let node_id = generate_random_node_id();
let node_addr: SocketAddr = "127.0.0.1:9000".parse()?;

let local_node = Node::new(node_id, node_addr);
let kad = KadProtocol::new(local_node).await;
let kad_shared: Arc<Mutex<KadProtocol>> = kad;

let service_manager = ServiceManager::new(device_origin, node_id, kad_shared.clone()).await;
service_manager.clone().start().await;
service_manager.register_service("chatroom-my-one", 9000, Some(120)).await;
service_manager.list_discovered_nodes().await;
```

### Expected Output
```
(INIT) Multicast socket set up on 224.0.0.251:5353
(ServiceManager) Service chatroom-my-one registered on port 9000
(EVENT) Discovered: chatroom-my-one
```

## Troubleshooting
If you encounter issues, consider:
- Ensuring that no other services are running on the same port.
- Verifying firewall and network settings to allow multicast traffic.
- Checking logs for error messages.

## Contributions
Contributions are welcome! Please open an issue or submit a pull request.

## License
This project is licensed under the MIT License.

