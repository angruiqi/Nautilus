
// protocols\handshake\src\traits.rs

pub trait CipherNegotiator {
    type CipherSuite: Clone + Send + Sync;
    type Error: std::fmt::Display;

    fn negotiate(
        &self,
        client_suites: &[Self::CipherSuite],
        server_suites: &[Self::CipherSuite],
    ) -> Result<Self::CipherSuite, Self::Error>;
}
pub trait Authenticator {
    type Key: Clone + Send + Sync;
    type Error: std::fmt::Display;

    fn authenticate(&self, public_key: &Self::Key, challenge: &[u8], signature: &[u8]) -> Result<bool, Self::Error>;
}

pub trait KeyAgreement {
    type SharedSecret: AsRef<[u8]> + Clone + Send + Sync;
    type PublicKey: Clone + Send + Sync;
    type Error: std::fmt::Display;

    fn agree(&self, public_key: &Self::PublicKey) -> Result<Self::SharedSecret, Self::Error>;
}

pub trait SessionKeyDeriver {
    type Key: Clone + Send + Sync;
    type Error: std::fmt::Display;

    fn derive(&self, shared_secret: &[u8], salt: &[u8], length: usize) -> Result<Self::Key, Self::Error>;
}