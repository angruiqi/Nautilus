// protocols/negotiation/negotiation_message.rs
use serde::{Serialize, Deserialize};
use crate::cipher_suite::CipherSuite;

#[derive(Serialize, Deserialize, Debug)]
pub enum NegotiationMessage {
    Proposal {
        cipher_suites: Vec<CipherSuite>,
        client_public_key: Vec<u8>,
    },
    Response {
        selected_suite: Option<CipherSuite>,
        server_public_key: Vec<u8>,
        shared_secret: Option<Vec<u8>>,
        signature: Option<Vec<u8>>,
    },
    Error(String),
}