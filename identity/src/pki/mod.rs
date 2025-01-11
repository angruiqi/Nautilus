//! PKI Module
//! 
//! This module provides various cryptographic key pair implementations,
//! enabled through feature flags. Each implementation adheres to the
//! `PKITraits` trait and supports operations like key generation, signing,
//! and verification.

// RSA key pair implementation
#[cfg(feature = "pki_rsa")]
mod rsa_keypair;
#[cfg(feature = "pki_rsa")]
pub use rsa_keypair::RSAkeyPair;

// SECP256K1 key pair implementation (under development)
#[cfg(feature = "secp256k1")]
mod secp256k1_keypair;
#[cfg(feature = "secp256k1")]
pub use secp256k1_keypair::SECP256K1KeyPair;

// ECDSA key pair implementation
#[cfg(feature = "ecdsa")]
mod ecdsa_keypair;
#[cfg(feature = "ecdsa")]
pub use ecdsa_keypair::ECDSAKeyPair;

// Ed25519 key pair implementation
#[cfg(feature = "ed25519")]
mod ed25519_keypair;
#[cfg(feature = "ed25519")]
pub use ed25519_keypair::Ed25519KeyPair;

// Dilithium key pair implementation
#[cfg(feature = "dilithium")]
mod dilithium_keypair;
#[cfg(feature = "dilithium")]
pub use dilithium_keypair::DilithiumKeyPair;

// SPHINCS+ key pair implementation
#[cfg(feature = "spincs")]
mod spincs_keypair;
#[cfg(feature = "spincs")]
pub use spincs_keypair::SPHINCSKeyPair;

// Falcon key pair implementation
#[cfg(feature = "falcon")]
mod falcon_keypair;
#[cfg(feature = "falcon")]
pub use falcon_keypair::FalconKeyPair;


// Kyber key pair Implementation
#[cfg(feature = "kyber")]
mod kyber_keypair;
#[cfg(feature = "kyber")]
pub use  kyber_keypair::KyberKeyPair;