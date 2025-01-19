// protocols\mdns\src\behaviour\mdns_service.rs
/// ================================== Imports ==========================================
/// ==================================Local Imports======================================
use crate::behaviour::records::{NodeRecord, ServiceRecord};
use crate::{DnsName, DnsPacket, DnsRecord, MdnsError, MdnsRegistry};
use crate::MdnsEvent;
/// ==================================External Imports===================================
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::net::UdpSocket;
use tokio::time::{self, Duration};
use tokio::sync::broadcast;
/// ==================================External Imports===================================
/// ================================== Imports ==========================================



/// ================================= MdnsService Struct ================================
/// Represents the mDNS service, including registry management and network communication.
pub struct MdnsService {
    socket: Arc<UdpSocket>,
    pub registry: Arc<MdnsRegistry>,
    event_sender: broadcast::Sender<MdnsEvent>,
    origin: Arc<RwLock<Option<String>>>, // Use RwLock to allow mutable access
}
/// ================================= MdnsService Struct ================================




impl MdnsService {
    /// Sets up a multicast UDP socket for mDNS communication.
    async fn setup_multicast_socket() -> Result<UdpSocket, MdnsError> {
        let multicast_addr = Ipv4Addr::new(224, 0, 0, 251);
        let local_addr = Ipv4Addr::UNSPECIFIED;
        let port = 5353;

        let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))
            .map_err(MdnsError::NetworkError)?;
        socket
            .set_reuse_address(true)
            .map_err(MdnsError::NetworkError)?;
        #[cfg(unix)]
        socket
            .set_reuse_port(true)
            .map_err(MdnsError::NetworkError)?;

        socket
            .bind(&SocketAddr::V4(SocketAddrV4::new(local_addr, port)).into())
            .map_err(MdnsError::NetworkError)?;

        let udp_socket = UdpSocket::from_std(socket.into()).map_err(MdnsError::NetworkError)?;
        udp_socket
            .join_multicast_v4(multicast_addr, local_addr)
            .map_err(MdnsError::NetworkError)?;

        println!(
            "(INIT) Multicast socket set up on {}:{}",
            multicast_addr, port
        );
        Ok(udp_socket)
    }

    /// Creates a new mDNS service instance.
    pub async fn new(origin: Option<String>) -> Result<Arc<Self>, MdnsError> {
        let socket = Self::setup_multicast_socket().await?;
        let registry = MdnsRegistry::new();
        let (event_sender, _) = broadcast::channel(100);
    
        Ok(Arc::new(Self {
            socket: Arc::new(socket),
            registry,
            event_sender,
            origin: Arc::new(RwLock::new(origin)), // Wrap the origin in RwLock
        }))
    }
   
    pub fn get_event_receiver(&self) -> broadcast::Receiver<MdnsEvent> {
        self.event_sender.subscribe() // Subscribe to the broadcast channel
    }
   
    /// Registers a local service to the registry.
    pub async fn register_local_service(
        &self,
        id: String,
        service_type: String,
        port: u16,
        ttl: Option<u32>,
        origin: String,
    ) -> Result<(), MdnsError> {
        let service = ServiceRecord {
            id: id.clone(),
            service_type,
            port,
            ttl,
            origin: origin.clone(),
            priority: Some(0),
            weight: Some(0),
        };
    
        self.registry
            .add_service(service.clone())
            .await
            .map_err(|e| MdnsError::Generic(e.to_string()))?;
    
        // Optionally, notify via event
        let _ = self.event_sender.send(MdnsEvent::Discovered(DnsRecord::SRV {
            name: DnsName::new(&service.id).unwrap(),
            ttl: service.ttl.unwrap_or(120),
            priority: service.priority.unwrap_or(0),
            weight: service.weight.unwrap_or(0),
            port: service.port,
            target: DnsName::new(&service.origin).unwrap(),
        }));
    
        Ok(())
    }
   
    /// Creates an mDNS advertisement packet from the service registry.
    pub async fn create_advertise_packet(&self) -> Result<DnsPacket, MdnsError> {
        let services = self.registry.list_services().await; // List all registered services
        let mut packet = DnsPacket::new();
        packet.flags = 0x8400; // Set response flags
    
        let local_ip = get_local_ipv4()
            .ok_or_else(|| MdnsError::Generic("Failed to get local IP".to_string()))?;
        let origin = {
            let origin_lock = self.origin.read().await;
            origin_lock
                .as_ref()
                .cloned()
                .unwrap_or_else(|| "UnknownOrigin.local".to_string())
        };
    
        if services.is_empty() {
            println!("(ADVERTISE) No local services to advertise.");
        } else {
            for service in services {
                println!("(ADVERTISE) Including service in packet: {:?}", service);
    
                packet.answers.push(DnsRecord::PTR {
                    name: DnsName::new(&service.service_type).unwrap(),
                    ttl: service.ttl.unwrap_or(120),
                    ptr_name: DnsName::new(&service.id).unwrap(),
                });
    
                packet.answers.push(DnsRecord::SRV {
                    name: DnsName::new(&service.id).unwrap(),
                    ttl: service.ttl.unwrap_or(120),
                    priority: service.priority.unwrap_or(0),
                    weight: service.weight.unwrap_or(0),
                    port: service.port,
                    target: DnsName::new(&origin).unwrap(),
                });
    
                packet.answers.push(DnsRecord::A {
                    name: DnsName::new(&service.origin).unwrap(),
                    ttl: service.ttl.unwrap_or(120),
                    ip: local_ip.octets(),
                });
            }
        }
    
        // Add a default A record for the node itself
        packet.answers.push(DnsRecord::A {
            name: DnsName::new(&origin).unwrap(),
            ttl: 120,
            ip: local_ip.octets(),
        });
    
        Ok(packet)
    }

    /// Sends an mDNS packet over the network.
    pub async fn send_packet(&self, packet: &DnsPacket) -> Result<(), MdnsError> {
        let bytes = packet.serialize();
        let multicast_addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353));
        self.socket
            .send_to(&bytes, multicast_addr)
            .await
            .map_err(MdnsError::NetworkError)?;

        // println!(
        //     "(SEND) Sent mDNS packet with {} answers",
        //     packet.answers.len()
        // );
        Ok(())
    }

    /// Periodically sends a PTR query for the given service type.
    pub async fn periodic_query(&self, service_type: &str, interval_secs: u64) {
        let mut ticker = time::interval(Duration::from_secs(interval_secs));
        loop {
            ticker.tick().await;
            // println!(
            //     "(QUERY) Sending periodic query for service type: {}",
            //     service_type
            // );
            let mut packet = DnsPacket::new();
            packet.flags = 0x0000;
            packet.questions.push(crate::DnsQuestion {
                qname: DnsName::new(service_type).unwrap(),
                qtype: 12,
                qclass: 1,
            });
            if let Err(err) = self.send_packet(&packet).await {
                eprintln!("(QUERY) Failed to send periodic query: {:?}", err);
            } else {
                println!(
                    "(QUERY) Periodic query sent for service type: {}",
                    service_type
                );
            }
        }
    }
    
    /// Advertises all local services as unsolicited mDNS responses.
    pub async fn advertise_services(&self) -> Result<(), MdnsError> {
        let packet = self.create_advertise_packet().await?;
        if packet.answers.is_empty() {
            println!("(ADVERTISE) No answers in the mDNS packet.");
        } else {
            println!(
                "(ADVERTISE) Sending mDNS packet with {} answers.",
                packet.answers.len()
            );
        }
        self.send_packet(&packet).await
    }

    /// Adds a node to the registry.
    async fn add_node_to_registry(
        &self,
        id: &str,
        ip_address: &str,
        ttl: Option<u32>,
    ) -> Result<(), MdnsError> {
        let normalized_id = id.trim_end_matches('.').to_string(); // Normalize the ID
        let ip_address = ip_address.to_string();
    
        // Retrieve all nodes
        let mut nodes = self.registry.list_nodes().await;
    
        // Check if the IP address is already assigned to a different node
        if let Some(conflicting_node) = nodes.iter().find(|node| node.ip_address == ip_address && node.id != normalized_id) {
            // println!(
            //     "(DISCOVERY) Conflict: IP address {} is already assigned to node {}",
            //     ip_address, conflicting_node.id
            // );
            return Err(MdnsError::Generic(format!(
                "IP conflict: {} is already assigned to {}",
                ip_address, conflicting_node.id
            )));
        }
    
        // Check if the node already exists
        if let Some(existing_node) = nodes.iter_mut().find(|node| node.id == normalized_id) {
            if existing_node.ip_address != ip_address {
                // println!(
                //     "(DISCOVERY) Updating node {} IP from {} to {}",
                //     normalized_id, existing_node.ip_address, ip_address
                // );
    
                // Update the node's IP address
                existing_node.ip_address = ip_address.clone();
    
                // Replace the node in the registry
                self.registry
                    .add_node(NodeRecord {
                        id: normalized_id.clone(),
                        ip_address: ip_address.clone(),
                        ttl,
                    })
                    .await
                    .map_err(|e| MdnsError::Generic(e.to_string()))?;
            } else {
                // println!(
                //     "(DISCOVERY) Node {} with IP {} already exists in the registry.",
                //     normalized_id, ip_address
                // );
            }
        } else {
            // Add a new node
            println!(
                "(DISCOVERY) Adding new node: {} with IP {}",
                normalized_id, ip_address
            );
    
            self.registry
                .add_node(NodeRecord {
                    id: normalized_id.clone(),
                    ip_address,
                    ttl,
                })
                .await
                .map_err(|e| MdnsError::Generic(e.to_string()))?;
        }
    
        Ok(())
    }
    
    /// Listens for incoming mDNS packets and processes them.
    pub async fn listen(&self) -> Result<(), MdnsError> {
        let mut buf = [0; 4096];
        loop {
            let (len, src) = self
                .socket
                .recv_from(&mut buf)
                .await
                .map_err(MdnsError::NetworkError)?;

            if let Ok(packet) = DnsPacket::parse(&buf[..len]) {
                let is_response = (packet.flags & 0x8000) != 0;
                if is_response {
                    self.process_response(&packet, &src).await;
                } else {
                    self.process_query(&packet, &src).await;
                }
            } else {
                eprintln!("(LISTEN) Failed to parse packet from {}", src);
            }
        }
    }

    /// Periodically prints the node registry for debugging.
    pub async fn print_node_registry(&self) {
        loop {
            time::sleep(Duration::from_secs(10)).await;
            let nodes = self.registry.list_nodes().await;
            println!("(NODE REGISTRY) Nodes: {:?}", nodes);
        }
    }

    /// Runs the mDNS service, spawning advertise, query, listen, and registry print tasks.
    pub async fn run(
        self: &Arc<Self>, // Borrow the Arc instead of consuming it
        service_type: String,
        query_interval: u64,
        advertise_interval: u64,
    ) {
        let advertise_service = Arc::clone(self);
        let query_service = Arc::clone(self);
        let listen_service = Arc::clone(self);
        let registry_service = Arc::clone(self);

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(advertise_interval)).await;
                if let Err(err) = advertise_service.advertise_services().await {
                    eprintln!("(ADVERTISE) Error: {:?}", err);
                }
            }
        });

        tokio::spawn(async move {
            query_service
                .periodic_query(&service_type, query_interval)
                .await;
        });

        tokio::spawn(async move {
            if let Err(err) = listen_service.listen().await {
                eprintln!("(LISTEN) Error: {:?}", err);
            }
        });

        tokio::spawn(async move {
            registry_service.print_node_registry().await;
        });
    }
    
    async fn process_response(&self, packet: &DnsPacket, src: &SocketAddr) {
        println!("Packet : {:?}", packet);
        
        // Ensure the source address is IPv4
        if let SocketAddr::V4(src_addr) = src {
            for answer in &packet.answers {
                match answer {
                    DnsRecord::A { name, ip, ttl } => {
                        let ip_address = Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]);
                        println!(
                            "(DISCOVERY) Discovered node: {} -> {} <=> {}",
                            name,
                            ip_address,
                            src_addr.ip() // Extract only the IP part of src_addr
                        );
    
                        // Add or update the node in the registry
                        if let Err(e) = self
                            .add_node_to_registry(&name.to_string(), &src_addr.ip().to_string(), Some(*ttl))
                            .await
                        {
                            eprintln!("(DISCOVERY) Failed to add node: {:?}", e);
                        }
    
                        // Optionally send discovery event
                        let _ = self.event_sender.send(MdnsEvent::Discovered(answer.clone()));
                        
                        // Log the updated registry state
                        let updated_nodes = self.registry.list_nodes().await;
                        println!("(REGISTRY) Current nodes: {:?}", updated_nodes);
                    }
                    _ => {}
                }
            }
        }
    }

    async fn process_query(&self, packet: &DnsPacket, src: &SocketAddr) {
        for question in &packet.questions {
            if question.qtype == 12 && question.qclass == 1 {
                let requested_service = question.qname.labels.join(".");
                let services = self.registry.list_services().await;
    
                let matching_services: Vec<_> = services
                    .into_iter()
                    .filter(|s| s.id.trim_end_matches('.').ends_with(&requested_service))
                    .collect();
    
                if matching_services.is_empty() {
                    println!("(QUERY) No matching service for '{}'", requested_service);
                    continue;
                }
    
                let mut response_packet = DnsPacket::new();
                response_packet.flags = 0x8400;
    
                let origin = {
                    let origin_lock = self.origin.read().await; // Acquire read lock
                    origin_lock.clone().unwrap_or_else(|| "UnknownOrigin.local".to_string())
                };
    
                for service in matching_services {
                    response_packet.answers.push(DnsRecord::PTR {
                        name: DnsName::new(&service.service_type).unwrap(),
                        ttl: service.ttl.unwrap_or(120),
                        ptr_name: DnsName::new(&service.id).unwrap(),
                    });
    
                    response_packet.answers.push(DnsRecord::SRV {
                        name: DnsName::new(&service.id).unwrap(),
                        ttl: service.ttl.unwrap_or(120),
                        priority: service.priority.unwrap_or(0),
                        weight: service.weight.unwrap_or(0),
                        port: service.port,
                        target: DnsName::new(&origin).unwrap(), // Use origin here
                    });
    
                    if let SocketAddr::V4(addr) = src {
                        response_packet.answers.push(DnsRecord::A {
                            name: DnsName::new(&origin).unwrap(), // Use origin here
                            ttl: service.ttl.unwrap_or(120),
                            ip: addr.ip().octets(),
                        });
                    }
                }
    
                if let Err(err) = self.send_packet(&response_packet).await {
                    eprintln!("(QUERY->RESP) Failed to send response: {:?}", err);
                }
            }
        }
    }
    
}

fn get_local_ipv4() -> Option<Ipv4Addr> {
    use std::net::{IpAddr, UdpSocket};

    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("8.8.8.8:80").ok()?;
    if let Ok(local_addr) = socket.local_addr() {
        if let IpAddr::V4(ip) = local_addr.ip() {
            return Some(ip);
        }
    }
    None
}
