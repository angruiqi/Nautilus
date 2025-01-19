use mdns::{MdnsService, MdnsEvent, DnsRecord};
use kad::kad_protocol::KadProtocol;
use kad::node::NodeId;
use std::sync::Arc;
use tokio::{sync::Mutex, spawn, signal};
use log::info;
use std::net::Ipv4Addr;

pub struct ServiceManager {
    mdns_service: Arc<MdnsService>,
    kad: Arc<Mutex<KadProtocol>>, 
    device_origin: String,
    node_id: NodeId,
}

impl ServiceManager {
    /// Initializes a new Service Manager with mDNS and Kad integration.
    pub async fn new(
        device_origin: &str,
        node_id: NodeId,
        kad: Arc<Mutex<KadProtocol>>
    ) -> Arc<Self> {
        let mdns_service = MdnsService::new(Some(device_origin.to_string()))
            .await
            .expect("Failed to initialize mDNS");

        Arc::new(Self {
            mdns_service,
            kad,
            device_origin: device_origin.to_string(),
            node_id,
        })
    }

    /// Start all services concurrently.
    pub async fn start(self: Arc<Self>) {
        let mdns_service_clone = Arc::clone(&self.mdns_service);
        let kad_clone_1 = Arc::clone(&self.kad);
        let kad_clone_2 = Arc::clone(&self.kad);

        // Start mDNS service
        spawn(async move {
            mdns_service_clone
                .run("submarine._udp.local".to_string(), 10, 30)
                .await;
        });

        // Start mDNS event handling
        let mdns_service_clone = Arc::clone(&self.mdns_service);
        spawn(async move {
            let mut event_receiver = mdns_service_clone.get_event_receiver();
            while let Ok(event) = event_receiver.recv().await {
                match event {
                    MdnsEvent::Discovered(record) => {
                        if let DnsRecord::A { name, ip, ttl: _ } = record {
                            info!("Discovered Node: {} -> {:?}", name, ip);
                            if let Ok(addr) = format!("{:?}:{}", Ipv4Addr::from(ip), 9000).parse() {
                                let discovered_node = kad::node::Node::new(kad::utils::generate_random_node_id(), addr);
                                let kad_lock = kad_clone_2.lock().await;
                                kad_lock.add_node(discovered_node).await;
                            }
                        }
                    }
                    MdnsEvent::Expired(record) => {
                        info!("Service expired: {:?}", record);
                    }
                    _ => {}
                }
            }
        });

        // Start Kad DHT service
        spawn(async move {
            let kad_lock = kad_clone_1.lock().await;
            kad_lock.run().await.expect("Kad service failed to start");
        });

        // Handle graceful shutdown
        signal::ctrl_c().await.expect("Failed to capture shutdown signal");
        info!("Shutdown signal received. Exiting...");
    }

    /// Register a local service via mDNS.
    pub async fn register_service(&self, service_type: &str, port: u16, ttl: Option<u32>) {
        self.mdns_service
            .register_local_service(
                hex::encode(self.node_id),
                service_type.to_string(),
                port,
                ttl,
                self.device_origin.clone(),
            )
            .await
            .expect("Failed to register service");
        info!("Service {} registered on port {}", hex::encode(self.node_id), port);
    }
    /// Retrieves and logs discovered nodes
    pub async fn list_discovered_nodes(&self) {
        let nodes = self.mdns_service.registry.list_nodes().await;
        if nodes.is_empty() {
            info!("No nodes discovered.");
        } else {
            info!("Discovered nodes:");
            for node in nodes {
                info!("{:?}", node);
            }
        }
    }
    
}
